package feeds

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Place is a PeeringDB facility or exchange with coordinates.
type Place struct {
	ID      int     `json:"id"`
	Name    string  `json:"name"`
	City    string  `json:"city,omitempty"`
	Country string  `json:"cc,omitempty"`
	Lat     float64 `json:"lat,omitempty"`
	Lon     float64 `json:"lon,omitempty"`
}

// Located reports whether coordinates are known.
func (p *Place) Located() bool { return p != nil && (p.Lat != 0 || p.Lon != 0) }

// PeeringDB is the bulk facility/IX/network table: an AS's profile and points
// of presence come from it without a single per-AS request (anonymous API
// access is rate limited to a few requests per hour).
type PeeringDB struct {
	Fac  map[int]*Place  `json:"fac"`
	IX   map[int]*Place  `json:"ix"`
	Nets map[int]*NetRec `json:"nets,omitempty"` // by ASN
}

// NetRec is a network record of the bulk dump.
type NetRec struct {
	ID              int         `json:"id"`
	Name            string      `json:"name"`
	AKA             string      `json:"aka,omitempty"`
	Website         string      `json:"website,omitempty"`
	Type            string      `json:"type,omitempty"`
	Traffic         string      `json:"traffic,omitempty"`
	Ratio           string      `json:"ratio,omitempty"`
	Scope           string      `json:"scope,omitempty"`
	Prefixes4       int         `json:"p4,omitempty"`
	Prefixes6       int         `json:"p6,omitempty"`
	Policy          string      `json:"policy,omitempty"`
	PolicyURL       string      `json:"policy_url,omitempty"`
	PolicyLocations string      `json:"policy_loc,omitempty"`
	PolicyContracts string      `json:"policy_contracts,omitempty"`
	IRRASSet        string      `json:"irr,omitempty"`
	IXCount         int         `json:"ixc,omitempty"`
	FacCount        int         `json:"facc,omitempty"`
	Updated         string      `json:"updated,omitempty"`
	Ports           []NetIXPort `json:"ports,omitempty"`
	Facs            []int       `json:"facs,omitempty"`
}

// NetIXPort is one exchange connection.
type NetIXPort struct {
	IX     int    `json:"ix"`
	Speed  int    `json:"speed,omitempty"`
	IPv4   string `json:"v4,omitempty"`
	IPv6   string `json:"v6,omitempty"`
	RSPeer bool   `json:"rs,omitempty"`
	Up     bool   `json:"up,omitempty"`
}

type pdbList[T any] struct {
	Data []T `json:"data"`
}

// BuildPeeringDB combines the /api/fac, /api/ix and /api/ixfac dumps. An
// exchange gets the centroid of its facilities in its own city (all of its
// facilities when none match the city).
// The network dumps (net, netixlan, netfac) are optional (nil skips them).
func BuildPeeringDB(facJSON, ixJSON, ixfacJSON, netJSON, netixlanJSON, netfacJSON []byte) (*PeeringDB, error) {
	var fac pdbList[struct {
		ID        int      `json:"id"`
		Name      string   `json:"name"`
		City      string   `json:"city"`
		Country   string   `json:"country"`
		Latitude  *float64 `json:"latitude"`
		Longitude *float64 `json:"longitude"`
	}]
	var ix pdbList[struct {
		ID      int    `json:"id"`
		Name    string `json:"name"`
		City    string `json:"city"`
		Country string `json:"country"`
	}]
	var ixfac pdbList[struct {
		IXID  int `json:"ix_id"`
		FacID int `json:"fac_id"`
	}]
	if err := json.Unmarshal(facJSON, &fac); err != nil {
		return nil, fmt.Errorf("peeringdb fac: %w", err)
	}
	if err := json.Unmarshal(ixJSON, &ix); err != nil {
		return nil, fmt.Errorf("peeringdb ix: %w", err)
	}
	if err := json.Unmarshal(ixfacJSON, &ixfac); err != nil {
		return nil, fmt.Errorf("peeringdb ixfac: %w", err)
	}
	if len(fac.Data) == 0 || len(ix.Data) == 0 {
		return nil, errors.New("peeringdb: empty dump")
	}
	db := &PeeringDB{Fac: map[int]*Place{}, IX: map[int]*Place{}}
	for _, f := range fac.Data {
		p := &Place{ID: f.ID, Name: f.Name, City: f.City, Country: f.Country}
		if f.Latitude != nil && f.Longitude != nil {
			p.Lat, p.Lon = round5(*f.Latitude), round5(*f.Longitude)
		}
		db.Fac[f.ID] = p
	}
	facsOf := map[int][]int{}
	for _, l := range ixfac.Data {
		facsOf[l.IXID] = append(facsOf[l.IXID], l.FacID)
	}
	for _, x := range ix.Data {
		p := &Place{ID: x.ID, Name: x.Name, City: x.City, Country: x.Country}
		var all, city [][2]float64
		for _, fid := range facsOf[x.ID] {
			f := db.Fac[fid]
			if !f.Located() {
				continue
			}
			all = append(all, [2]float64{f.Lat, f.Lon})
			if strings.EqualFold(strings.TrimSpace(f.City), strings.TrimSpace(x.City)) {
				city = append(city, [2]float64{f.Lat, f.Lon})
			}
		}
		pts := city
		if len(pts) == 0 {
			pts = all
		}
		if len(pts) > 0 {
			var la, lo float64
			for _, q := range pts {
				la += q[0]
				lo += q[1]
			}
			p.Lat, p.Lon = round5(la/float64(len(pts))), round5(lo/float64(len(pts)))
		}
		db.IX[x.ID] = p
	}
	if netJSON != nil {
		if err := addNets(db, netJSON, netixlanJSON, netfacJSON); err != nil {
			return nil, err
		}
	}
	return db, nil
}

func addNets(db *PeeringDB, netJSON, netixlanJSON, netfacJSON []byte) error {
	var nets pdbList[struct {
		ID              int    `json:"id"`
		ASN             int    `json:"asn"`
		Name            string `json:"name"`
		AKA             string `json:"aka"`
		Website         string `json:"website"`
		InfoType        string `json:"info_type"`
		InfoTraffic     string `json:"info_traffic"`
		InfoRatio       string `json:"info_ratio"`
		InfoScope       string `json:"info_scope"`
		InfoPrefixes4   int    `json:"info_prefixes4"`
		InfoPrefixes6   int    `json:"info_prefixes6"`
		PolicyGeneral   string `json:"policy_general"`
		PolicyURL       string `json:"policy_url"`
		PolicyLocations string `json:"policy_locations"`
		PolicyContracts string `json:"policy_contracts"`
		IRRASSet        string `json:"irr_as_set"`
		IXCount         int    `json:"ix_count"`
		FacCount        int    `json:"fac_count"`
		Updated         string `json:"updated"`
	}]
	if err := json.Unmarshal(netJSON, &nets); err != nil {
		return fmt.Errorf("peeringdb net: %w", err)
	}
	if len(nets.Data) == 0 {
		return errors.New("peeringdb: empty net dump")
	}
	db.Nets = make(map[int]*NetRec, len(nets.Data))
	byID := map[int]*NetRec{}
	for _, n := range nets.Data {
		if n.ASN <= 0 {
			continue
		}
		r := &NetRec{ID: n.ID, Name: n.Name, AKA: n.AKA, Website: n.Website, Type: n.InfoType, Traffic: n.InfoTraffic,
			Ratio: n.InfoRatio, Scope: n.InfoScope, Prefixes4: n.InfoPrefixes4, Prefixes6: n.InfoPrefixes6,
			Policy: n.PolicyGeneral, PolicyURL: n.PolicyURL, PolicyLocations: n.PolicyLocations, PolicyContracts: n.PolicyContracts,
			IRRASSet: n.IRRASSet, IXCount: n.IXCount, FacCount: n.FacCount, Updated: n.Updated}
		db.Nets[n.ASN] = r
		byID[n.ID] = r
	}
	if netixlanJSON != nil {
		var l pdbList[struct {
			NetID       int     `json:"net_id"`
			ASN         int     `json:"asn"`
			IXID        int     `json:"ix_id"`
			Speed       int     `json:"speed"`
			IPAddr4     *string `json:"ipaddr4"`
			IPAddr6     *string `json:"ipaddr6"`
			IsRSPeer    bool    `json:"is_rs_peer"`
			Operational bool    `json:"operational"`
		}]
		if err := json.Unmarshal(netixlanJSON, &l); err != nil {
			return fmt.Errorf("peeringdb netixlan: %w", err)
		}
		for _, x := range l.Data {
			r := byID[x.NetID]
			if r == nil {
				r = db.Nets[x.ASN]
			}
			if r == nil {
				continue
			}
			p := NetIXPort{IX: x.IXID, Speed: x.Speed, RSPeer: x.IsRSPeer, Up: x.Operational}
			if x.IPAddr4 != nil {
				p.IPv4 = *x.IPAddr4
			}
			if x.IPAddr6 != nil {
				p.IPv6 = *x.IPAddr6
			}
			r.Ports = append(r.Ports, p)
		}
	}
	if netfacJSON != nil {
		var l pdbList[struct {
			NetID    int `json:"net_id"`
			FacID    int `json:"fac_id"`
			LocalASN int `json:"local_asn"`
		}]
		if err := json.Unmarshal(netfacJSON, &l); err != nil {
			return fmt.Errorf("peeringdb netfac: %w", err)
		}
		for _, x := range l.Data {
			r := byID[x.NetID]
			if r == nil {
				r = db.Nets[x.LocalASN]
			}
			if r != nil {
				r.Facs = append(r.Facs, x.FacID)
			}
		}
	}
	return nil
}
