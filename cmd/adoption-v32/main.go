package main

import("crypto/sha256";"encoding/hex";"encoding/json";"fmt";"os";"sort";"strings")
const kitPath="adoption-conformance-kit/ENTITY_V3_2_ADOPTION_CLEANROOM_KIT.min.json"
const kitSHA="44e7a00f910c89aced3b3c1b5e9cba486809ca313e9bfb4b7bc9266095c10c14"
const expected="1eb59e09ab08da86bfd8584df4a64ba331f7bbbce3d236b9b94f351606c90e18"
var primitives=[]string{"ENTITY","AUTHORITY","RIGHT","EVENT","VALUE"}
var lifecycle=[]string{"DCO","INSTRUMENT","LISTING","DISCLOSURE","ORDER_RFQ_AUCTION","PRICE_DISCOVERY","TRADE","CLEARING","SETTLEMENT","ENTITLEMENT","USAGE","DERIVED_OUTPUT","ECONOMIC_CONSEQUENCE"}
var providers=map[string]bool{"AWS_S3":true,"AZURE_BLOB":true,"GOOGLE_CLOUD_STORAGE":true,"SNOWFLAKE":true,"DATABRICKS":true,"POSTGRESQL":true,"SQL_SERVER":true,"LOCAL_FILESYSTEM":true,"HTTP_API":true}
var standards=map[string]bool{"ODRL":true,"W3C_VC":true,"DID":true,"GAIA_X":true,"IDS":true}
type Vector struct{Expect string `json:"expect"`;Name string `json:"name"`;Record map[string]any `json:"record"`}
type Kit struct{Profile map[string]any `json:"profile"`;Vectors []Vector `json:"vectors"`}
type Row struct{Accepted bool `json:"accepted"`;Expected string `json:"expected"`;Name string `json:"name"`;Ok bool `json:"ok"`}
func sha(b []byte)string{x:=sha256.Sum256(b);return hex.EncodeToString(x[:])}
func str(r map[string]any,k string)string{v,_:=r[k].(string);return v}
func boo(r map[string]any,k string,w bool)bool{v,ok:=r[k].(bool);return ok&&v==w}
func hex64(v any)bool{s,ok:=v.(string);if !ok||len(s)!=64{return false};for _,c:=range s{if !(c>='0'&&c<='9'||c>='a'&&c<='f'){return false}};return true}
func strs(v any)([]string,bool){a,ok:=v.([]any);if !ok{return nil,false};z:=make([]string,len(a));for i,x:=range a{s,ok:=x.(string);if !ok{return nil,false};z[i]=s};return z,true}
func arrEq(v any,w []string)bool{z,ok:=strs(v);if !ok||len(z)!=len(w){return false};for i:=range z{if z[i]!=w[i]{return false}};return true}
func rules(v any)bool{a,ok:=v.([]any);if !ok||len(a)==0{return false};for _,x:=range a{q,ok:=x.(map[string]any);if !ok{return false};e:=str(q,"effect");if e!="ALLOW"&&e!="REQUIRE"&&e!="PROHIBIT"{return false};xs,ok:=strs(q["actions"]);if !ok||len(xs)==0{return false};ys:=append([]string{},xs...);sort.Strings(ys);seen:=map[string]bool{};for i,s:=range xs{if s==""||s!=strings.ToUpper(s)||seen[s]||s!=ys[i]{return false};seen[s]=true}};return true}
func valid(r map[string]any)bool{switch str(r,"schema"){
case"entity-v3-rights-passport-v1":return arrEq(r["core_primitives"],primitives)&&rules(r["rights"])&&boo(r,"provider_custody_is_not_authority",true)&&boo(r,"underlying_data_not_silently_transferred",true)&&boo(r,"legal_effect_is_deployment_specific",true)
case"entity-v3-custody-locator-v1":return providers[str(r,"provider")]&&hex64(r["content_sha256"])&&boo(r,"provider_is_authority",false)&&boo(r,"credentials_included",false)&&boo(r,"entity_identity_changes_with_provider",false)
case"entity-v3-standards-mapping-v1":return standards[str(r,"source_standard")]&&hex64(r["source_sha256"])&&boo(r,"silent_semantic_equivalence",false)&&boo(r,"external_standard_is_not_entity_authority",true)
case"entity-v3-external-credential-evidence-v1":return str(r,"source_standard")=="W3C_VC"&&hex64(r["credential_sha256"])&&boo(r,"credential_is_evidence_not_entity_authority",true)
case"entity-v3-resolver-deployment-v1":n,ok:=r["minimum_resolvers"].(float64);return str(r,"mode")=="FEDERATED"&&ok&&n>=2&&boo(r,"resolver_is_not_authority",true)&&boo(r,"single_provider_dependency_prohibited",true)&&boo(r,"fail_closed",true)
case"entity-v3-exchange-adoption-profile-v1":return boo(r,"market_engine_preserved",true)&&boo(r,"rights_are_traded_not_bytes",true)&&arrEq(r["market_lifecycle"],lifecycle)
case"entity-v3-adoption-profile-status-v1":return arrEq(r["core_primitives"],primitives)&&boo(r,"core_semantics_changed",false)&&boo(r,"market_engine_preserved",true)
case"entity-v3-legal-classification-assertion-v1":return str(r,"asserted_by")!=""&&str(r,"classification")!=""&&boo(r,"classification_is_assertion_not_protocol_legal_truth",true)};return false}
func canonical(v any)string{switch x:=v.(type){case map[string]any:ks:=make([]string,0,len(x));for k:=range x{ks=append(ks,k)};sort.Strings(ks);parts:=make([]string,len(ks));for i,k:=range ks{kb,_:=json.Marshal(k);parts[i]=string(kb)+":"+canonical(x[k])};return "{"+strings.Join(parts,",")+"}";case []any:parts:=make([]string,len(x));for i,z:=range x{parts[i]=canonical(z)};return "["+strings.Join(parts,",")+"]";default:b,_:=json.Marshal(x);return string(b)}}
func main(){raw,e:=os.ReadFile(kitPath);if e!=nil||sha(raw)!=kitSHA{panic("sealed kit SHA-256 mismatch")};var kit Kit;if json.Unmarshal(raw,&kit)!=nil{panic("kit json")};rows:=make([]Row,0,len(kit.Vectors));passed:=0;for _,v:=range kit.Vectors{a:=valid(v.Record);ok:=a==(v.Expect=="VALID");if ok{passed++};rows=append(rows,Row{a,v.Expect,v.Name,ok})};sort.Slice(rows,func(i,j int)bool{return rows[i].Name<rows[j].Name});rb,_:=json.Marshal(rows);var ra any;json.Unmarshal(rb,&ra);summary:=map[string]any{"schema":"entity-v3.2-adoption-cleanroom-result-v1","profile":"ENTITY-ADOPTION-LAYER","adoption_invariants":kit.Profile["adoption_invariants"],"vectors":ra};result:=sha([]byte(canonical(summary)));overall:=passed==16&&result==expected;out:=map[string]any{"implementation":"go","kit_sha256":kitSHA,"vectors_passed":passed,"vectors_total":16,"result_sha256":result,"expected_result_sha256":expected,"overall_valid":overall};b,_:=json.MarshalIndent(out,"","  ");fmt.Println(string(b));if !overall{os.Exit(1)}}
