package geo

import (
	"fmt"
	"math"
)

// FiberKmPerMs is the propagation speed of light in fibre (~2/3 c).
const FiberKmPerMs = 200.0

// SlackKm absorbs coordinate imprecision (city centroids, metro areas).
const SlackKm = 150.0

// DistanceKm is the great-circle distance between two points.
func DistanceKm(lat1, lon1, lat2, lon2 float64) float64 {
	const r = 6371.0
	p1, p2 := lat1*math.Pi/180, lat2*math.Pi/180
	dp := (lat2 - lat1) * math.Pi / 180
	dl := (lon2 - lon1) * math.Pi / 180
	a := math.Sin(dp/2)*math.Sin(dp/2) + math.Cos(p1)*math.Cos(p2)*math.Sin(dl/2)*math.Sin(dl/2)
	return 2 * r * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
}

// MinRTTms is the physically lowest possible round trip time over distance km.
func MinRTTms(km float64) float64 { return 2 * km / FiberKmPerMs }

// MaxKm is the farthest a reply with rtt ms can come from (one-way radius).
func MaxKm(rttMs float64) float64 { return rttMs * FiberKmPerMs / 2 }

// Point is a located hop used by the validator.
type Point struct {
	Lat, Lon float64
	RTT      float64 // min RTT from the source in ms
	Name     string
}

// Feasible checks whether location c with min RTT rc is compatible with an
// anchor a: the source S is within MaxKm(ra) of a and within MaxKm(rc) of c,
// so dist(a,c) <= MaxKm(ra)+MaxKm(rc) by the triangle inequality.
func Feasible(a Point, c Point) (bool, float64) {
	d := DistanceKm(a.Lat, a.Lon, c.Lat, c.Lon)
	limit := MaxKm(a.RTT) + MaxKm(c.RTT) + SlackKm
	return d <= limit, d
}

// FeasibleFromOrigin checks a candidate against a known source location.
func FeasibleFromOrigin(o *Point, c Point) (bool, float64) {
	if o == nil {
		return true, 0
	}
	d := DistanceKm(o.Lat, o.Lon, c.Lat, c.Lon)
	return d <= MaxKm(c.RTT)+SlackKm, d
}

// violation describes why a candidate is impossible.
func violation(d, rtt float64) string {
	return fmt.Sprintf("%.0f km away needs ≥ %.1f ms RTT, measured %.1f ms", d, MinRTTms(math.Max(0, d-SlackKm)), rtt)
}
