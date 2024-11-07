package derp

import (
	"encoding/json"
	"net/http"
	"tailscale.com/tailcfg"
)

// Load loads derp map from multiple sources and returns a merged map
func Load(srcs []string) (_ *tailcfg.DERPMap, err error) {
	var result = &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{},
	}

	for _, src := range srcs {
		var req *http.Request
		if req, err = http.NewRequest("GET", src, http.NoBody); err != nil {
			return nil, err
		}

		var resp *http.Response
		if resp, err = http.DefaultClient.Do(req); err != nil {
			return nil, err
		}

		var dm tailcfg.DERPMap
		if err = json.NewDecoder(resp.Body).Decode(&dm); err != nil {
			_ = resp.Body.Close()
			return nil, err
		}

		_ = resp.Body.Close()

		for id, r := range dm.Regions {
			result.Regions[id] = r
		}
	}

	return result, nil
}
