package diagnostics

import (
	"bufio"
	"compress/gzip"
	"container/heap"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const evidenceBudget int64 = 64 << 20
const evidenceTail int64 = 8 << 20

type evidenceItem struct {
	at       time.Time
	row      map[string]any
	id, path string
}
type evidenceHeap []evidenceItem

func (h evidenceHeap) Len() int           { return len(h) }
func (h evidenceHeap) Less(i, j int) bool { return h[i].at.Before(h[j].at) }
func (h evidenceHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *evidenceHeap) Push(v any)        { *h = append(*h, v.(evidenceItem)) }
func (h *evidenceHeap) Pop() any          { v := *h; x := v[len(v)-1]; *h = v[:len(v)-1]; return x }
func keepLatest(h *evidenceHeap, item evidenceItem, limit int) bool {
	if len(*h) < limit {
		heap.Push(h, item)
		return false
	}
	if item.at.After((*h)[0].at) {
		heap.Pop(h)
		heap.Push(h, item)
	}
	return true
}
func sortedEvidence(h evidenceHeap) []map[string]any {
	sort.Slice(h, func(i, j int) bool { return h[i].at.After(h[j].at) })
	out := make([]map[string]any, 0, len(h))
	for _, x := range h {
		out = append(out, x.row)
	}
	return out
}

// readEvidenceWindow retains latest records by their timestamps, not random shard suffixes.
// Plain files use seekable tails. Gzip has no reverse index; its decoded scan has
// an explicit byte budget and reports partial coverage rather than claiming absence.
func readEvidenceWindow(ctx context.Context, o Options, since time.Time) (summary, failures, logs []map[string]any, paths map[string]string, coverage map[string]any, errs []string, truncated bool) {
	var sh, fh, lh evidenceHeap
	paths = map[string]string{}
	ranges := []map[string]any{}
	remaining := evidenceBudget
	coverage = map[string]any{"byteBudget": evidenceBudget, "sinceUtc": since.UTC(), "requestFilterApplied": o.RequestID != "", "exhaustive": true, "requestFound": false}
	for _, section := range []struct {
		root     string
		requests bool
	}{{filepath.Join(o.DataRoot, "captures", "summary"), true}, {filepath.Join(o.DataRoot, "logs", "service"), false}} {
		entries, e := os.ReadDir(section.root)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			errs = append(errs, "evidence:directory_unavailable")
			truncated = true
			continue
		}
		type candidate struct {
			entry    os.DirEntry
			modified time.Time
		}
		candidates := []candidate{}
		for _, entry := range entries {
			if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".jsonl") && !strings.HasSuffix(entry.Name(), ".jsonl.gz")) {
				continue
			}
			info, e := entry.Info()
			if e == nil {
				candidates = append(candidates, candidate{entry, info.ModTime()})
			}
		}
		sort.Slice(candidates, func(i, j int) bool { return candidates[i].modified.After(candidates[j].modified) })
		if len(candidates) > 64 {
			candidates = candidates[:64]
			truncated = true
			coverage["fileLimitReached"] = true
		}
		for _, candidate := range candidates {
			if ctx.Err() != nil {
				errs = append(errs, "evidence:cancelled")
				truncated = true
				break
			}
			if remaining <= 0 {
				truncated = true
				coverage["byteBudgetExhausted"] = true
				break
			}
			path := filepath.Join(section.root, candidate.entry.Name())
			if !safeFile(path) {
				errs = append(errs, "evidence:file_unavailable")
				truncated = true
				continue
			}
			file, e := os.Open(path)
			if e != nil {
				errs = append(errs, "evidence:file_unavailable")
				truncated = true
				continue
			}
			info, e := file.Stat()
			if e != nil {
				file.Close()
				continue
			}
			compressed := strings.HasSuffix(path, ".gz")
			limit := remaining
			start := int64(0)
			if !compressed {
				if o.RequestID == "" && limit > evidenceTail {
					limit = evidenceTail
				}
				start = info.Size() - limit
				if start < 0 {
					start = 0
				}
				_, e = file.Seek(start, io.SeekStart)
			}
			rangeInfo := map[string]any{"fileHash": hashIdentifier(candidate.entry.Name()), "compressed": compressed, "offsetStart": start, "offsetEnd": info.Size(), "modifiedAtUtc": info.ModTime().UTC()}
			if start > 0 {
				truncated = true
				rangeInfo["partialReason"] = "TAIL_WINDOW"
			}
			var reader io.Reader = file
			var gz *gzip.Reader
			if compressed {
				gz, e = gzip.NewReader(file)
				if e == nil {
					reader = gz
					rangeInfo["offsetUnits"] = "decoded_bytes"
					rangeInfo["offsetEnd"] = nil
				}
			}
			if e != nil {
				file.Close()
				errs = append(errs, "evidence:file_unavailable")
				truncated = true
				continue
			}
			// One extra byte distinguishes an exact budget boundary from complete EOF.
			counted := &countReader{reader: io.LimitReader(reader, limit+1)}
			scanner := bufio.NewScanner(counted)
			scanner.Buffer(make([]byte, 4096), 256<<10)
			skip := start > 0
			for scanner.Scan() {
				if skip {
					skip = false
					continue
				}
				if counted.n > limit {
					truncated = true
					rangeInfo["partialReason"] = "BYTE_BUDGET"
					break
				}
				if ctx.Err() != nil {
					truncated = true
					rangeInfo["partialReason"] = "CANCELLED"
					break
				}
				var row map[string]any
				if json.Unmarshal(scanner.Bytes(), &row) != nil {
					continue
				}
				lower := lowerObject(row)
				at, ok := rowTime(lower)
				if !ok {
					continue
				}
				if first, ok := rangeInfo["oldestObservedUtc"].(time.Time); !ok || at.Before(first) {
					rangeInfo["oldestObservedUtc"] = at
				}
				if last, ok := rangeInfo["newestObservedUtc"].(time.Time); !ok || at.After(last) {
					rangeInfo["newestObservedUtc"] = at
				}
				if at.Before(since) {
					continue
				}
				id := str(lower["requestid"])
				if section.requests && o.RequestID != "" && !strings.EqualFold(id, o.RequestID) {
					continue
				}
				item := evidenceItem{at: at, row: sanitizeRow(row), id: id, path: str(lower["markdownpath"])}
				if section.requests {
					coverage["requestFound"] = true
					if keepLatest(&sh, item, 200) {
						truncated = true
					}
					status, _ := lower["statuscode"].(float64)
					if status >= 400 || str(lower["errorcode"]) != "" || strings.EqualFold(str(lower["outcome"]), "failed") || strings.EqualFold(str(lower["outcome"]), "error") {
						if keepLatest(&fh, item, 200) {
							truncated = true
						}
					}
				} else {
					if keepLatest(&lh, item, 10000) {
						truncated = true
					}
				}
			}
			if scanner.Err() != nil {
				errs = append(errs, "evidence:line_unavailable")
				truncated = true
				rangeInfo["partialReason"] = "READ_OR_LINE_LIMIT"
			}
			if counted.n > limit {
				truncated = true
				rangeInfo["partialReason"] = "BYTE_BUDGET"
			}
			remaining -= counted.n
			rangeInfo["bytesRead"] = counted.n
			if !compressed {
				rangeInfo["offsetEnd"] = start + counted.n
			}
			ranges = append(ranges, rangeInfo)
			if gz != nil {
				gz.Close()
			}
			file.Close()
		}
	}
	sort.Slice(fh, func(i, j int) bool { return fh[i].at.After(fh[j].at) })
	for _, x := range fh {
		if len(paths) >= 50 {
			break
		}
		if uuidPattern.MatchString(x.id) {
			paths[x.id] = x.path
		}
	}
	coverage["ranges"] = ranges
	coverage["bytesRead"] = evidenceBudget - remaining
	coverage["exhaustive"] = !truncated
	return sortedEvidence(sh), sortedEvidence(fh), sortedEvidence(lh), paths, coverage, errs, truncated
}

type countReader struct {
	reader io.Reader
	n      int64
}

func (r *countReader) Read(b []byte) (int, error) {
	n, e := r.reader.Read(b)
	r.n += int64(n)
	return n, e
}
