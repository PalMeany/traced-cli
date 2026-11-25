package geo

import (
	"strconv"
	"strings"
	"unicode"
)

// City is an entry of the built-in location dictionary.
type City struct {
	Code    string  `json:"code"`
	Name    string  `json:"name"`
	Country string  `json:"country"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
}

// cityData: code|name|cc|lat|lon|aliases (comma separated, lower case).
// Aliases cover alternative IATA codes, backbone naming conventions
// (Arelion/Telia twelve99 codes, NTT CLLI-like 6 letter codes, Level3/Lumen
// full city names, Russian operator abbreviations) and city names.
// A leading '~' on an alias marks it as weak (ambiguous English word): it only
// counts when glued to digits (e.g. "sea1") or in a strong position.
const cityData = `
mow|Moscow|RU|55.7558|37.6173|msk,moscow,moskva,svo,dme,vko,m9,m10,mmts9,mmts10,m9p,mosc,mskix,ixmsk
led|St Petersburg|RU|59.9343|30.3351|spb,spe,piter,petersburg,stpetersburg,saintpetersburg,sankt,spbix
svx|Yekaterinburg|RU|56.8389|60.6057|ekb,ekt,yekaterinburg,ekaterinburg,ekat
ovb|Novosibirsk|RU|55.0084|82.9357|nsk,novosibirsk,nsb,novosib
krr|Krasnodar|RU|45.0355|38.9753|krasnodar,krd
kzn|Kazan|RU|55.7963|49.1088|kazan,kzn
rov|Rostov-on-Don|RU|47.2357|39.7015|rostov,rnd,rostovondon
goj|Nizhny Novgorod|RU|56.2965|43.9361|nnov,nnovgorod,nizhny,nnv,nng
kuf|Samara|RU|53.1959|50.1002|samara,smr,sam
vvo|Vladivostok|RU|43.1155|131.8855|vladivostok,vlad
khv|Khabarovsk|RU|48.4827|135.0838|khabarovsk,khb
kja|Krasnoyarsk|RU|56.0153|92.8932|krasnoyarsk,krsk,krs
oms|Omsk|RU|54.9885|73.3242|omsk
cek|Chelyabinsk|RU|55.1644|61.4368|chelyabinsk,chel,chl
ufa|Ufa|RU|54.7388|55.9721|ufa
pee|Perm|RU|58.0105|56.2502|perm,prm
vog|Volgograd|RU|48.708|44.5133|volgograd,vlg,vgg
voz|Voronezh|RU|51.672|39.1843|voronezh,vrn
ikt|Irkutsk|RU|52.287|104.305|irkutsk,irk
tjm|Tyumen|RU|57.153|65.5343|tyumen,tmn
kgd|Kaliningrad|RU|54.7104|20.4522|kaliningrad,klg
mmk|Murmansk|RU|68.9585|33.0827|murmansk,mrm
aer|Sochi|RU|43.5855|39.7231|sochi
tof|Tomsk|RU|56.4846|84.9476|tomsk,tsk
bax|Barnaul|RU|53.3548|83.7698|barnaul,brn
arh|Arkhangelsk|RU|64.5401|40.5433|arkhangelsk,arkh
mcx|Makhachkala|RU|42.9849|47.5047|makhachkala,mhk
ijk|Izhevsk|RU|56.8526|53.2045|izhevsk,izh
ulv|Ulyanovsk|RU|54.3142|48.4031|ulyanovsk
rtw|Saratov|RU|51.5331|46.0342|saratov,srt
yks|Yakutsk|RU|62.0355|129.6755|yakutsk
ren|Orenburg|RU|51.7682|55.0969|orenburg,orb
tya|Tula|RU|54.1931|37.6173|tula
yar|Yaroslavl|RU|57.6261|39.8845|yaroslavl,yrs,yar
kem|Kemerovo|RU|55.3547|86.0873|kemerovo
nbc|Naberezhnye Chelny|RU|55.7436|52.3958|chelny
sgc|Surgut|RU|61.254|73.3962|surgut
mrv|Mineralnye Vody|RU|44.2251|43.0817|minvody,stavropol,stv
kiv|Chisinau|MD|47.0105|28.8638|chisinau,kishinev
iev|Kyiv|UA|50.4501|30.5234|kbp,kiev,kyiv,kie
ods|Odesa|UA|46.4825|30.7233|odessa,odesa
hrk|Kharkiv|UA|49.9935|36.2304|kharkiv,kharkov
lwo|Lviv|UA|49.8397|24.0297|lviv,lvov
dnk|Dnipro|UA|48.4647|35.0462|dnipro,dnepr
msq|Minsk|BY|53.9006|27.559|minsk,mns
ala|Almaty|KZ|43.222|76.8512|almaty,alma
nqz|Astana|KZ|51.1694|71.4491|tse,astana,nursultan
tas|Tashkent|UZ|41.2995|69.2401|tashkent
evn|Yerevan|AM|40.1792|44.4991|yerevan
tbs|Tbilisi|GE|41.7151|44.8271|tbilisi
gyd|Baku|AZ|40.4093|49.8671|baku
fru|Bishkek|KG|42.8746|74.5698|bishkek
dyu|Dushanbe|TJ|38.5598|68.787|dushanbe
rix|Riga|LV|56.9496|24.1052|riga
tll|Tallinn|EE|59.437|24.7536|tallinn,tln
vno|Vilnius|LT|54.6872|25.2797|vilnius,vln
fra|Frankfurt|DE|50.1109|8.6821|frankfurt,ffm,frnk,frnkge,fft,frf
ams|Amsterdam|NL|52.3676|4.9041|amsterdam,adm,amst,amstnl,amsix,asd
lon|London|GB|51.5074|-0.1278|lhr,lcy,lgw,stn,london,ldn,lond,londen,lonuk,lnd,slough,docklands
man|Manchester|GB|53.4808|-2.2426|manchester,mchester,~man
edi|Edinburgh|GB|55.9533|-3.1883|edinburgh
dub|Dublin|IE|53.3498|-6.2603|dublin,dbln
par|Paris|FR|48.8566|2.3522|cdg,ory,paris,prs,pars,parsfr
mrs|Marseille|FR|43.2965|5.3698|marseille,mars,mrsl
lys|Lyon|FR|45.764|4.8357|lyon,lyo
nce|Nice|FR|43.7102|7.262|nice
bod|Bordeaux|FR|44.8378|-0.5792|bordeaux
sxb|Strasbourg|FR|48.5734|7.7521|strasbourg
mad|Madrid|ES|40.4168|-3.7038|madrid,mdrd,mdrdsp
bcn|Barcelona|ES|41.3874|2.1686|barcelona,brcl
lis|Lisbon|PT|38.7223|-9.1393|lisbon,lisboa,~lis
opo|Porto|PT|41.1579|-8.6291|porto
vie|Vienna|AT|48.2082|16.3738|vienna,wien,wienat,vix
zrh|Zurich|CH|47.3769|8.5417|zurich,zuerich,zur,zrch
gva|Geneva|CH|46.2044|6.1432|geneva,geneve
prg|Prague|CZ|50.0755|14.4378|prague,praha,prag,prha
brq|Brno|CZ|49.1951|16.6068|brno
waw|Warsaw|PL|52.2297|21.0122|warsaw,warszawa,wars,~war,wrs,wrsw
ktw|Katowice|PL|50.2649|19.0238|katowice
krk|Krakow|PL|50.0647|19.945|krakow,cracow
poz|Poznan|PL|52.4064|16.9252|poznan
wro|Wroclaw|PL|51.1079|17.0385|wroclaw
gdn|Gdansk|PL|54.352|18.6466|gdansk
lcj|Lodz|PL|51.7592|19.456|lodz
sto|Stockholm|SE|59.3293|18.0686|arn,stockholm,stk,stoc,stocse,sth,sthlm,bma
got|Gothenburg|SE|57.7089|11.9746|gothenburg,goteborg,gbg
mmx|Malmo|SE|55.6049|13.0038|malmo
hel|Helsinki|FI|60.1699|24.9384|helsinki,hls,hki,hlsnk
osl|Oslo|NO|59.9139|10.7522|oslo
bgo|Bergen|NO|60.3913|5.3221|bergen
cph|Copenhagen|DK|55.6761|12.5683|copenhagen,kbn,kbh,cop,cpnh
aar|Aarhus|DK|56.1629|10.2039|aarhus
ber|Berlin|DE|52.52|13.405|berlin,txl,brln,brlnde,bln
ham|Hamburg|DE|53.5511|9.9937|hamburg,hbg,hmbg,~ham
muc|Munich|DE|48.1351|11.582|munich,muenchen,mnch,mchn
dus|Dusseldorf|DE|51.2277|6.7735|dusseldorf,duesseldorf,ddf,dsdf
cgn|Cologne|DE|50.9375|6.9603|cologne,koeln,koln
str|Stuttgart|DE|48.7758|9.1829|stuttgart,~str
nue|Nuremberg|DE|49.4521|11.0767|nuremberg,nuernberg,nbg
lej|Leipzig|DE|51.3397|12.3731|leipzig,lpz
han|Hanover|DE|52.3759|9.732|hannover,hanover
bru|Brussels|BE|50.8503|4.3517|brussels,bruxelles,brx,brsl
anr|Antwerp|BE|51.2194|4.4025|antwerp
lux|Luxembourg|LU|49.6116|6.1319|luxembourg
rtm|Rotterdam|NL|51.9244|4.4777|rotterdam,rtd
ein|Eindhoven|NL|51.4416|5.4697|eindhoven
mil|Milan|IT|45.4642|9.19|mxp,~lin,milan,milano,mlan,mlanit
fco|Rome|IT|41.9028|12.4964|rome,roma,~rom
trn|Turin|IT|45.0703|7.6869|turin,torino
pmo|Palermo|IT|38.1157|13.3615|palermo
ath|Athens|GR|37.9838|23.7275|athens,athina
skg|Thessaloniki|GR|40.6401|22.9444|thessaloniki
sof|Sofia|BG|42.6977|23.3219|sofia
otp|Bucharest|RO|44.4268|26.1025|buh,bucharest,bucuresti,bcr
clj|Cluj-Napoca|RO|46.7712|23.6236|cluj
bud|Budapest|HU|47.4979|19.0402|budapest,bpt,bdps
beg|Belgrade|RS|44.7866|20.4489|belgrade,beograd
zag|Zagreb|HR|45.815|15.9819|zagreb
lju|Ljubljana|SI|46.0569|14.5058|ljubljana
bts|Bratislava|SK|48.1486|17.1077|bratislava
ist|Istanbul|TR|41.0082|28.9784|istanbul,ista,ibs
esb|Ankara|TR|39.9334|32.8597|ankara,ank
kef|Reykjavik|IS|64.1466|-21.9426|reykjavik,rek
tlv|Tel Aviv|IL|32.0853|34.7818|telaviv
lca|Larnaca|CY|34.9003|33.6232|larnaca,nicosia
mla|Valletta|MT|35.8989|14.5146|malta
dxb|Dubai|AE|25.2048|55.2708|dubai,dxb
auh|Abu Dhabi|AE|24.4539|54.3773|abudhabi
doh|Doha|QA|25.2854|51.531|doha
bah|Manama|BH|26.0667|50.5577|bahrain,manama
ruh|Riyadh|SA|24.7136|46.6753|riyadh
jed|Jeddah|SA|21.4858|39.1925|jeddah
kwi|Kuwait City|KW|29.3759|47.9774|kuwait
mct|Muscat|OM|23.588|58.3829|muscat
ika|Tehran|IR|35.6892|51.389|thr,tehran
cai|Cairo|EG|30.0444|31.2357|cairo
jnb|Johannesburg|ZA|-26.2041|28.0473|johannesburg,jhb
cpt|Cape Town|ZA|-33.9249|18.4241|capetown
los|Lagos|NG|6.5244|3.3792|lagos
nbo|Nairobi|KE|-1.2921|36.8219|nairobi
mba|Mombasa|KE|-4.0435|39.6682|mombasa
cmn|Casablanca|MA|33.5731|-7.5898|casablanca
tun|Tunis|TN|36.8065|10.1815|tunis
acc|Accra|GH|5.6037|-0.187|accra
jib|Djibouti|DJ|11.5721|43.1456|djibouti
sin|Singapore|SG|1.3521|103.8198|singapore,~sg,sngp,sgp,sngpsi
hkg|Hong Kong|HK|22.3193|114.1694|hongkong,~hk,hkng,hkgehk
nrt|Tokyo|JP|35.6762|139.6503|hnd,tyo,tokyo,toky,tky,tokyjp,tko
kix|Osaka|JP|34.6937|135.5023|osa,osaka,osak
icn|Seoul|KR|37.5665|126.978|~sel,seoul,seol
pus|Busan|KR|35.1796|129.0756|busan
tpe|Taipei|TW|25.033|121.5654|taipei,tpe
pek|Beijing|CN|39.9042|116.4074|bjs,beijing,pkx
pvg|Shanghai|CN|31.2304|121.4737|sha,shanghai
can|Guangzhou|CN|23.1291|113.2644|guangzhou,~can
szx|Shenzhen|CN|22.5431|114.0579|shenzhen
ctu|Chengdu|CN|30.5728|104.0668|chengdu
bkk|Bangkok|TH|13.7563|100.5018|bangkok
kul|Kuala Lumpur|MY|3.139|101.6869|kualalumpur
cgk|Jakarta|ID|-6.2088|106.8456|jkt,jakarta
sub|Surabaya|ID|-7.2575|112.7521|surabaya
mnl|Manila|PH|14.5995|120.9842|manila
sgn|Ho Chi Minh City|VN|10.8231|106.6297|hochiminh,saigon,hcm
hph|Hanoi|VN|21.0278|105.8342|hanoi,hni
bom|Mumbai|IN|19.076|72.8777|mumbai,mum
del|New Delhi|IN|28.7041|77.1025|delhi,newdelhi,~del
maa|Chennai|IN|13.0827|80.2707|chennai
blr|Bangalore|IN|12.9716|77.5946|bangalore,bengaluru
hyd|Hyderabad|IN|17.385|78.4867|hyderabad
ccu|Kolkata|IN|22.5726|88.3639|kolkata
khi|Karachi|PK|24.8607|67.0011|karachi
cmb|Colombo|LK|6.9271|79.8612|colombo
dac|Dhaka|BD|23.8103|90.4125|dhaka
uln|Ulaanbaatar|MN|47.8864|106.9057|ulaanbaatar
syd|Sydney|AU|-33.8688|151.2093|sydney,sydn
mel|Melbourne|AU|-37.8136|144.9631|melbourne,~mel
bne|Brisbane|AU|-27.4698|153.0251|brisbane
per|Perth|AU|-31.9505|115.8605|perth,~per
adl|Adelaide|AU|-34.9285|138.6007|adelaide
akl|Auckland|NZ|-36.8485|174.7633|auckland
iad|Ashburn|US|39.0438|-77.4874|ashburn,~ash,asbn,asbnva,dca,wdc,washington,wash,was,reston,sterling
jfk|New York|US|40.7128|-74.006|nyc,lga,ewr,newyork,nyk,nycm,nwrk,nwrknj,newark,nyiix,nymny
bos|Boston|US|42.3601|-71.0589|boston,bstn,~bos
phl|Philadelphia|US|39.9526|-75.1652|philadelphia,phla
atl|Atlanta|US|33.749|-84.388|atlanta,atln,atlnga
mia|Miami|US|25.7617|-80.1918|miami,mmi,miam,miamfl
ord|Chicago|US|41.8781|-87.6298|chi,chicago,chcg,chcgil
dfw|Dallas|US|32.7767|-96.797|dallas,~dal,dls,dlls,dllstx
iah|Houston|US|29.7604|-95.3698|hou,houston,hstn
den|Denver|US|39.7392|-104.9903|denver,dnvr
phx|Phoenix|US|33.4484|-112.074|phoenix,phnx
lax|Los Angeles|US|34.0522|-118.2437|losangeles,lsan,lsanca
sjc|San Jose|US|37.3382|-121.8863|sanjose,sjo,snjs,snjsca,svl,santaclara
sfo|San Francisco|US|37.7749|-122.4194|sanfrancisco,snfc
pao|Palo Alto|US|37.4419|-122.143|paloalto,plal
sea|Seattle|US|47.6062|-122.3321|seattle,sttl,sttlwa,~sea
pdx|Portland|US|45.5152|-122.6784|portland,ptld
slc|Salt Lake City|US|40.7608|-111.891|saltlake,sltl
las|Las Vegas|US|36.1699|-115.1398|lasvegas,lsvg,~las
msp|Minneapolis|US|44.9778|-93.265|minneapolis,mpls
dtw|Detroit|US|42.3314|-83.0458|detroit,dtrt
stl|St. Louis|US|38.627|-90.1994|stlouis,stls
mci|Kansas City|US|39.0997|-94.5786|kansascity,kscy
clt|Charlotte|US|35.2271|-80.8431|charlotte,chrl
tpa|Tampa|US|27.9506|-82.4572|tampa
bna|Nashville|US|36.1627|-86.7816|nashville
san|San Diego|US|32.7157|-117.1611|sandiego,~san
smf|Sacramento|US|38.5816|-121.4944|sacramento
hnl|Honolulu|US|21.3069|-157.8583|honolulu
cmh|Columbus|US|39.9612|-82.9988|columbus
qro|Queretaro|MX|20.5888|-100.3899|queretaro
mex|Mexico City|MX|19.4326|-99.1332|mexico,mexicocity
yyz|Toronto|CA|43.6532|-79.3832|~tor,toronto,trnt
yul|Montreal|CA|45.5017|-73.5673|mtl,montreal,mtrl
yvr|Vancouver|CA|49.2827|-123.1207|vancouver,vncv
yyc|Calgary|CA|51.0447|-114.0719|calgary
gru|Sao Paulo|BR|-23.5505|-46.6333|~sao,saopaulo,spo,gru
gig|Rio de Janeiro|BR|-22.9068|-43.1729|~rio,riodejaneiro
for|Fortaleza|BR|-3.7319|-38.5267|fortaleza,~for
eze|Buenos Aires|AR|-34.6037|-58.3816|bue,buenosaires
scl|Santiago|CL|-33.4489|-70.6693|santiago,stgo
bog|Bogota|CO|4.711|-74.0721|bogota
lim|Lima|PE|-12.0464|-77.0428|~lim,lima
pty|Panama City|PA|8.9824|-79.5199|panama
`

var (
	cityByCode  = map[string]*City{}
	aliasIndex  = map[string]*City{} // strong aliases
	weakAliases = map[string]*City{}
	cityByName  = map[string]*City{} // normalized name -> city
	allCities   []*City
)

func init() {
	for _, line := range strings.Split(cityData, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f := strings.Split(line, "|")
		if len(f) < 5 {
			continue
		}
		lat, _ := strconv.ParseFloat(f[3], 64)
		lon, _ := strconv.ParseFloat(f[4], 64)
		c := &City{Code: f[0], Name: f[1], Country: f[2], Lat: lat, Lon: lon}
		allCities = append(allCities, c)
		cityByCode[c.Code] = c
		if _, ok := aliasIndex[c.Code]; !ok {
			aliasIndex[c.Code] = c
		}
		cityByName[normName(c.Name)] = c
		if len(f) > 5 {
			for _, a := range strings.Split(f[5], ",") {
				a = strings.TrimSpace(a)
				if a == "" {
					continue
				}
				if strings.HasPrefix(a, "~") {
					weakAliases[a[1:]] = c
					delete(aliasIndex, a[1:])
					continue
				}
				if _, ok := aliasIndex[a]; !ok {
					aliasIndex[a] = c
				}
			}
		}
	}
	// IATA codes that are also common words are weak even as primary code
	for _, w := range []string{"man", "can", "for", "per", "san", "sea", "del", "las", "lim", "mel", "ham", "bos", "str", "lis"} {
		if c, ok := aliasIndex[w]; ok {
			weakAliases[w] = c
			delete(aliasIndex, w)
		}
	}
}

func normName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) {
			b.WriteRune(r)
		}
	}
	n := b.String()
	repl := map[string]string{"sãopaulo": "saopaulo", "zürich": "zurich", "düsseldorf": "dusseldorf", "münchen": "munich",
		"köln": "cologne", "kyiv": "kyiv", "kiev": "kyiv", "moskva": "moscow", "stpetersburg": "stpetersburg",
		"saintpetersburg": "stpetersburg", "sanktpeterburg": "stpetersburg", "ekaterinburg": "yekaterinburg",
		"frankfurtammain": "frankfurt", "frankfurtmain": "frankfurt", "praha": "prague", "wien": "vienna",
		"warszawa": "warsaw", "newyorkcity": "newyork", "hochiminhcity": "hochiminhcity", "bucuresti": "bucharest"}
	if v, ok := repl[n]; ok {
		return v
	}
	return n
}

// LookupCity finds a city by IATA code, alias or name.
func LookupCity(s string) *City {
	k := strings.ToLower(strings.TrimSpace(s))
	if c, ok := cityByCode[k]; ok {
		return c
	}
	if c, ok := aliasIndex[k]; ok {
		return c
	}
	if c, ok := cityByName[normName(s)]; ok {
		return c
	}
	if c, ok := aliasIndex[normName(s)]; ok {
		return c
	}
	return nil
}

// LookupCityIn is LookupCity restricted to a country (when cc != "").
func LookupCityIn(name, cc string) *City {
	c := LookupCity(name)
	if c == nil {
		return nil
	}
	if cc != "" && !strings.EqualFold(c.Country, cc) {
		return nil
	}
	return c
}

// CityCount returns the number of built-in locations.
func CityCount() int { return len(allCities) }
