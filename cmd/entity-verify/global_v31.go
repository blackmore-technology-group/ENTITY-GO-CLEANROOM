package main

import (
 "bufio"
 "os"
 "path/filepath"
 "sort"
 "strings"
)

var globalKinds=map[string]bool{"SCHEMA":true,"RIGHT":true,"EVENT":true,"CAPABILITY":true,"ASSET_CLASS":true,"TRUST_FRAMEWORK":true,"DISPUTE_AUTHORITY":true,"ATTESTATION_CLASS":true}
var globalTopology=map[string]bool{"CORE":true,"REGIONAL":true,"EDGE":true,"SATELLITE":true,"OFFLINE":true}
var globalScarcity=map[string]bool{"RIGHT":true,"ENTITLEMENT":true,"CAPACITY":true,"DURATION":true,"JURISDICTION":true,"USAGE_QUANTITY":true,"DERIVATION":true,"PARTICIPATION":true,"TRANSFERABILITY":true}

func garr(v any,k string) []any { a,_:=obj(v)[k].([]any);return a }
func ghex64(v any,k string) bool { s:=str(v,k);if len(s)!=64{return false};for _,c:=range s{if !(c>='0'&&c<='9'||c>='a'&&c<='f'){return false}};return true }
func sortedUniqueStrings(a []any) bool { s:=make([]string,len(a));for i,x:=range a{s[i]=x.(string)};z:=append([]string{},s...);sort.Strings(z);u:=[]string{};for _,x:=range z{if len(u)==0||u[len(u)-1]!=x{u=append(u,x)}};if len(u)!=len(s){return false};for i:=range s{if s[i]!=u[i]{return false}};return true }

func validGlobalRecord(r any) bool {
 switch str(r,"schema") {
 case "entity-v3-jurisdiction-profile-v1":
  if !boolean(r,"legal_effect_is_deployment_specific"){return false};for _,x:=range garr(r,"rules"){e:=str(x,"effect");if e!="ALLOW"&&e!="REQUIRE"&&e!="PROHIBIT"{return false};if len(garr(x,"actions"))==0{return false}};return true
 case "entity-v3-semantic-term-v1": return globalKinds[str(r,"kind")]&&ghex64(r,"definition_sha256")&&str(r,"status")=="ACTIVE"
 case "entity-v3-topology-node-v1": return globalTopology[str(r,"topology_class")]&&boolean(r,"infrastructure_membership_is_not_sovereign_authority")
 case "entity-v3-purpose-bound-access-v1": return len(garr(r,"purposes"))>0&&len(garr(r,"actions"))>0&&num(r,"max_uses")>=0
 case "entity-v3-offline-envelope-v1": return ghex64(r,"payload_sha256")&&num(r,"sequence")>=0&&num(r,"expires_at_ms")>num(r,"created_at_ms")
 case "entity-v3-crypto-transition-v1": return boolean(r,"downgrade_after_transition_prohibited")&&num(r,"old_retire_at_ms")>=num(r,"dual_sign_from_ms")
 case "entity-v3-data-economic-capital-v1": return boolean(r,"information_bytes_are_not_declared_scarce")&&ghex64(r,"provenance_root")&&ghex64(r,"content_sha256")
 case "entity-v3-bounded-economic-interest-v1":
  a:=garr(r,"actions");s:=garr(r,"scarcity_sources");if len(a)==0||!sortedUniqueStrings(a)||!boolean(r,"underlying_information_remains_nonrival"){return false};hasRight:=false;for _,x:=range s{v:=x.(string);if !globalScarcity[v]{return false};if v=="RIGHT"{hasRight=true}};p:=num(r,"participation_bps");return hasRight&&p>=0&&p<=10000
 }
 return false
}

func verifyGlobalChecksums(root string) bool {
 f,e:=os.Open(filepath.Join(root,"SHA256SUMS.txt"));if e!=nil{return false};defer f.Close();sc:=bufio.NewScanner(f)
 for sc.Scan(){line:=strings.TrimPrefix(sc.Text(),"\ufeff");if strings.TrimSpace(line)==""{continue};parts:=strings.SplitN(line,"  ",2);if len(parts)!=2{return false};b,e:=os.ReadFile(filepath.Join(root,filepath.FromSlash(parts[1])));if e!=nil||shaBytes(b)!=parts[0]{return false}}
 return sc.Err()==nil
}

func runGlobalCampaign(root string) map[string]any {
 checksums:=verifyGlobalChecksums(root);profile:=obj(load(filepath.Join(root,"ENTITY_GLOBAL_CLEANROOM_PROFILE.json")));manifest:=obj(load(filepath.Join(root,"vectors","VECTOR_MANIFEST.json")))
 rows:=[]any{};for _,ee:=range garr(manifest,"vectors"){e:=obj(ee);file:=str(e,"file");p:=obj(load(filepath.Join(root,"vectors",file)));accepted:=validGlobalRecord(p["record"]);expected:=str(p,"expect");rows=append(rows,map[string]any{"name":strings.TrimSuffix(file,".json"),"accepted":accepted,"expected":expected,"ok":accepted==(expected=="VALID")})}
 sort.Slice(rows,func(i,j int)bool{return str(rows[i],"name")<str(rows[j],"name")})
 summary:=map[string]any{"schema":"entity-v3.1-global-cleanroom-result-v1","profile":"ENTITY-GLOBAL-INFRASTRUCTURE","doctrine_invariants":profile["doctrine_invariants"],"vectors":rows}
 result:=shaText(canon(summary));passed:=0;valid:=0;for _,rr:=range rows{r:=obj(rr);if boolean(r,"ok"){passed++};if boolean(r,"accepted"){valid++}}
 all:=checksums&&passed==len(rows)&&result==str(profile,"expected_result_sha256")&&int64(valid)==num(profile,"valid_vectors")&&int64(len(rows)-valid)==num(profile,"invalid_vectors")
 return map[string]any{"implementation":"go","checksums_pass":checksums,"vectors_passed":passed,"vectors_total":len(rows),"result_sha256":result,"expected_result_sha256":str(profile,"expected_result_sha256"),"doctrine_invariants":profile["doctrine_invariants"],"overall_valid":all,"results":rows}
}
