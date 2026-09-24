package main
import("crypto/sha256";"encoding/hex";"encoding/json";"fmt";"os";"sort";"strings")
const kitPath="reality-conformance-kit/ENTITY_V3_3_REALITY_CLEANROOM_KIT.min.json"
const kitSHA="f8b39ee01fb7346f33a57530e925b545d2bf9a770c7ec60724e28a4971d55a46"
const expected="82bd1f1fb328edd37a26d8ea60ede5a599c7d9af5027bffd73b9e52843b5a51d"
var primitives=[]string{"ENTITY","AUTHORITY","RIGHT","EVENT","VALUE"}
var states=set("OBSERVED","ASSERTED","INFERRED","ATTESTED","EXTERNALLY_VERIFIED","ADJUDICATED","DISPUTED","REVOKED","UNKNOWN")
var evidence=set("SENSOR_OBSERVATION","DOCUMENT","REGISTRY_RECORD","LAB_RESULT","PAYMENT_RECORD","IMAGE","API_RESPONSE","CERTIFICATE","COURT_RECORD","OTHER")
var anchors=set("GOVERNMENT_REGISTRY","SENSOR_NETWORK","BANK_SETTLEMENT","LAB_SYSTEM","SUPPLY_CHAIN_SYSTEM","CORPORATE_REGISTRY","COURT_RECORD","CERTIFICATE_AUTHORITY","OTHER")
var nodes=set("SOURCE_DATA","DCO","RIGHT","LICENSE","USAGE","DERIVED_ASSET","PRODUCT","TRANSACTION","REVENUE","SETTLEMENT","CONTRIBUTOR")
var edges=set("ORIGINATED_FROM","AUTHORIZED_BY","LICENSED_AS","USED_IN","DERIVED_FROM","PRODUCED","GENERATED","SETTLED_AS","CONTRIBUTED_TO")
func set(xs ...string)map[string]bool{m:=map[string]bool{};for _,x:=range xs{m[x]=true};return m}
func sha(b []byte)string{x:=sha256.Sum256(b);return hex.EncodeToString(x[:])}
func str(r map[string]any,k string)string{v,_:=r[k].(string);return v}
func boo(r map[string]any,k string,w bool)bool{v,ok:=r[k].(bool);return ok&&v==w}
func hex64(v any)bool{s,ok:=v.(string);if !ok||len(s)!=64{return false};for _,c:=range s{if !(c>='0'&&c<='9'||c>='a'&&c<='f'){return false}};return true}
func refs(v any,nonempty bool)bool{a,ok:=v.([]any);if !ok||nonempty&&len(a)==0{return false};xs:=make([]string,len(a));for i,x:=range a{s,ok:=x.(string);if !ok||s==""{return false};xs[i]=s};ys:=append([]string{},xs...);sort.Strings(ys);seen:=map[string]bool{};for i,s:=range xs{if seen[s]||s!=ys[i]{return false};seen[s]=true};return true}
func arrEq(v any,w []string)bool{a,ok:=v.([]any);if !ok||len(a)!=len(w){return false};for i,x:=range a{s,ok:=x.(string);if !ok||s!=w[i]{return false}};return true}
func valid(r map[string]any)bool{switch str(r,"schema"){
case"entity-v3-evidence-object-v1":return evidence[str(r,"evidence_type")]&&hex64(r["content_sha256"])&&boo(r,"signature_proves_attribution_not_objective_truth",true)&&boo(r,"immutable_evidence_record",true)
case"entity-v3-evidence-bound-claim-v1":return states[str(r,"state")]&&hex64(r["value_sha256"])&&refs(r["evidence_refs"],false)&&boo(r,"claim_is_not_objective_truth",true)&&boo(r,"state_is_typed_not_absolute",true)
case"entity-v3-claim-status-transition-v1":return states[str(r,"from_state")]&&states[str(r,"to_state")]&&str(r,"from_state")!=str(r,"to_state")&&refs(r["evidence_refs"],false)&&boo(r,"history_rewrite_prohibited",true)&&boo(r,"transition_does_not_establish_objective_truth",true)
case"entity-v3-attestation-authority-grant-v1":return refs(r["scopes"],true)&&hex64(r["authority_evidence_sha256"])&&boo(r,"attestation_authority_is_scope_limited",true)&&boo(r,"attestation_does_not_create_legal_truth",true)
case"entity-v3-attestation-v1":return str(r,"grant_id")!=""&&str(r,"scope")!=""&&refs(r["evidence_refs"],true)&&boo(r,"attestation_is_evidence_not_objective_truth",true)
case"entity-v3-external-reality-anchor-v1":return anchors[str(r,"anchor_type")]&&hex64(r["endpoint_descriptor_sha256"])&&boo(r,"credentials_included",false)&&boo(r,"external_system_is_not_automatic_entity_authority",true)
case"entity-v3-external-reality-snapshot-v1":return hex64(r["record_sha256"])&&refs(r["verifier_evidence_refs"],false)&&boo(r,"external_record_is_evidence_not_protocol_truth",true)&&boo(r,"record_may_be_contested_or_superseded",true)
case"entity-v3-causal-economic-node-v1":o,_:=r["economic_observation"].(map[string]any);obsok:=len(o)==0||boo(o,"market_observation_is_not_accounting_fair_value",true)&&boo(o,"protocol_does_not_determine_legal_entitlement",true);return nodes[str(r,"node_type")]&&refs(r["evidence_refs"],false)&&refs(r["event_refs"],false)&&obsok
case"entity-v3-causal-economic-edge-v1":return edges[str(r,"edge_type")]&&str(r,"from_node_id")!=str(r,"to_node_id")&&refs(r["evidence_refs"],true)&&refs(r["authority_refs"],false)&&refs(r["participation_rule_refs"],false)&&boo(r,"causality_is_evidence_bound_not_assumed",true)&&boo(r,"economic_attribution_is_not_accounting_fair_value",true)
case"entity-v3-verifiable-reality-status-v1":return arrEq(r["core_primitives"],primitives)&&boo(r,"core_semantics_changed",false)&&boo(r,"market_engine_preserved",true)&&boo(r,"reality_claims_are_evidence_bound",true)&&boo(r,"cryptographic_verification_is_not_objective_truth",true)&&boo(r,"protocol_verification_is_not_objective_truth",true)};return false}
func canonical(v any)string{switch x:=v.(type){case map[string]any:ks:=make([]string,0,len(x));for k:=range x{ks=append(ks,k)};sort.Strings(ks);parts:=make([]string,len(ks));for i,k:=range ks{kb,_:=json.Marshal(k);parts[i]=string(kb)+":"+canonical(x[k])};return"{"+strings.Join(parts,",")+"}";case []any:parts:=make([]string,len(x));for i,z:=range x{parts[i]=canonical(z)};return"["+strings.Join(parts,",")+"]";default:b,_:=json.Marshal(x);return string(b)}}
type Case struct{ID string `json:"id"`;Expect string `json:"expect"`;Record map[string]any `json:"record"`}
type Kit struct{Cases []Case `json:"cases"`;Expected string `json:"expected_result_sha256"`}
func main(){raw,e:=os.ReadFile(kitPath);if e!=nil||sha(raw)!=kitSHA{panic("sealed v3.3 kit SHA-256 mismatch")};var kit Kit;if json.Unmarshal(raw,&kit)!=nil{panic("kit json")};sort.Slice(kit.Cases,func(i,j int)bool{return kit.Cases[i].ID<kit.Cases[j].ID});trans:=make([]any,0,len(kit.Cases));passed:=0;for _,c:=range kit.Cases{actual:="INVALID";if valid(c.Record){actual="VALID"};if actual==c.Expect{passed++};trans=append(trans,map[string]any{"id":c.ID,"actual":actual})};result:=sha([]byte(canonical(trans)));overall:=passed==20&&result==expected&&kit.Expected==expected;out:=map[string]any{"implementation":"go","kit_sha256":kitSHA,"vectors_passed":passed,"vectors_total":20,"result_sha256":result,"expected_result_sha256":expected,"overall_valid":overall};b,_:=json.MarshalIndent(out,"","  ");fmt.Println(string(b));if !overall{os.Exit(1)}}
