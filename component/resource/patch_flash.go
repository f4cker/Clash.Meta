package resource

import "time"

// Interval is how often the fetcher pulls its resource again; zero never.
func (f *Fetcher[V]) Interval() time.Duration {
	return f.interval
}
