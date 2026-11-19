package credential

import "context"

// RegionalLogin is one region of a device login whose tokens are partitioned
// by region: a token minted for one partition is refused by the others, and
// the provider's CLI keeps one login per site, so a login made at the default
// site cannot mint another partition's token.
//
// Each region is authorized on its own and stored as a credential record of
// its own (Platform, "<primary>--<site>"). Its consent and revocation follow
// the primary record's, and a machine reaches it only through a grant for the
// primary platform that names the region: the regional record is never a
// platform of its own (Providers.Known is false for it).
type RegionalLogin struct {
	// Region is the token partition a machine asks for.
	Region string `json:"region"`
	// Site is where the provider logs in for it.
	Site string `json:"site"`
	// Platform is the record holding the login.
	Platform string `json:"platform"`
	// Title is the page copy.
	Title string `json:"title"`
}

// RegionalDeviceLogin is implemented by a DeviceLogin with regional logins.
// Complete and Mint serve the regional records as well: the pending payload
// and the record's Platform say which region they belong to.
type RegionalDeviceLogin interface {
	Regions() []RegionalLogin
	// BeginRegion starts a login at the region's site.
	BeginRegion(ctx context.Context, region string) DeviceLoginBegin
}

// RegionalPlatformSeparator joins a primary platform and a regional site. The
// result must stay a valid stored platform name (store.IsCredentialPlatform):
// a pod from before regional logins still decodes the person's records.
const RegionalPlatformSeparator = "--"

// RegionalPlatform is the record name of site's login under primary.
func RegionalPlatform(primary, site string) string {
	return primary + RegionalPlatformSeparator + site
}

// Regions lists primary's regional logins (nil when it has none).
func (p Providers) Regions(primary string) []RegionalLogin {
	if regional, ok := p.DeviceLogin(primary).(RegionalDeviceLogin); ok {
		return regional.Regions()
	}
	return nil
}

// RegionalLoginOf finds the regional login a record platform names, and its
// primary platform; ok=false for anything else (a primary platform included).
func (p Providers) RegionalLoginOf(platform string) (login RegionalLogin, primary string, ok bool) {
	for _, provider := range p.DeviceLogins {
		primary := provider.Descriptor().Platform
		for _, login := range p.Regions(primary) {
			if login.Platform == platform {
				return login, primary, true
			}
		}
	}
	return RegionalLogin{}, "", false
}
