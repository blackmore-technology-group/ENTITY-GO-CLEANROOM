package main

import (
 "bytes"
 "crypto/aes"
 "crypto/cipher"
 "crypto/ed25519"
 "crypto/sha256"
 "crypto/x509"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "os"
 "path/filepath"
 "sort"
)

var required=[]string{"transaction_record","manifests","asset_provenance","rights","licence","usage_receipt","license_settlement","value_record","digital_commodity","corporate_authorization","capital","share_settlement","event_ledger","external_trust_anchors"}
func parse(b []byte) any { d:=json.NewDecoder(bytes.NewReader(b)); d.UseNumber(); var v any; if err:=d.Decode(&v);err!=nil{panic(err)};return v }
func load(p string) any { b,e:=os.ReadFile(p);if e!=nil{panic(e)};return parse(bytes.TrimPrefix(b,[]byte{0xef,0xbb,0xbf})) }
func canon(v any) string { b,e:=json.Marshal(v);if e!=nil{panic(e)};return string(b) }
func shaBytes(b []byte) string { h:=sha256.Sum256(b);return hex.EncodeToString(h[:]) }
func shaText(s string) string { return shaBytes([]byte(s)) }
func obj(v any) map[string]any { if x,ok:=v.(map[string]any);ok{return x};return map[string]any{} }
func str(v any,k string) string { x,_:=obj(v)[k].(string);return x }
func num(v any,k string) int64 { switch x:=obj(v)[k].(type){case json.Number:n,_:=x.Int64();return n;case float64:return int64(x)};return 0 }
func boolean(v any,k string) bool { x,_:=obj(v)[k].(bool);return x }
func add(es *[]string,c string){for _,x:=range *es{if x==c{return}};*es=append(*es,c)}
func verifySig(b any) bool {
 s:=obj(obj(b)["signature"]);if str(s,"alg")!="Ed25519"{return false}
 der,e:=base64.StdEncoding.DecodeString(str(s,"public_key_spki_der_b64"));if e!=nil{return false}
 k,e:=x509.ParsePKIXPublicKey(der);if e!=nil{return false};pk,ok:=k.(ed25519.PublicKey);if !ok{return false}
 sig,e:=base64.StdEncoding.DecodeString(str(s,"sig_b64"));if e!=nil{return false}
 h:=map[string]any{"schema":str(b,"schema"),"transaction_id":str(b,"transaction_id"),"issuer_entity_id":str(b,"issuer_entity_id"),"transaction_root_sha256":str(b,"transaction_root_sha256")}
 return ed25519.Verify(pk,[]byte(canon(h)),sig)
}
func verifyLedger(l any,es *[]string) bool {
 evs,ok:=obj(l)["events"].([]any);if !ok{add(es,"LEDGER_SEQUENCE_INVALID");return false};prev:=string(bytes.Repeat([]byte("0"),64))
 for i,e:=range evs { if num(e,"sequence")!=int64(i+1){add(es,"LEDGER_SEQUENCE_INVALID");return false};if str(e,"prev_hash")!=prev{add(es,"LEDGER_PREV_HASH_INVALID");return false};expected:=shaText(prev+":"+canon(obj(e)["payload"]));if str(e,"event_hash")!=expected{add(es,"LEDGER_EVENT_HASH_INVALID");return false};prev=expected }
 cp:=obj(obj(l)["checkpoint"]);if num(cp,"sequence")!=int64(len(evs))||str(cp,"head_hash")!=prev{add(es,"LEDGER_CHECKPOINT_INVALID");return false};return true
}
func verifyBundle(b any) map[string]any {
 es:=[]string{};ev:=obj(obj(b)["evidence"]);root:=shaText(canon(ev));rootOk:=root==str(b,"transaction_root_sha256");if !rootOk{add(&es,"ROOT_MISMATCH")}
 sigOk:=verifySig(b);if !sigOk{add(&es,"SIGNATURE_INVALID")};reqOk:=true;for _,s:=range required{if _,ok:=ev[s];!ok{reqOk=false;add(&es,"MISSING_SECTION:"+s)}};cross:=true
 if reqOk {
  tr:=obj(ev["transaction_record"]);p:=obj(ev["asset_provenance"]);r:=obj(ev["rights"]);l:=obj(ev["licence"]);u:=obj(ev["usage_receipt"]);s:=obj(ev["license_settlement"]);v:=obj(ev["value_record"]);d:=obj(ev["digital_commodity"]);ca:=obj(ev["corporate_authorization"]);c:=obj(ev["capital"]);ss:=obj(ev["share_settlement"])
  if str(p,"asset_id")!=str(tr,"asset_id"){cross=false;add(&es,"PROVENANCE_ASSET_MISMATCH")};if str(r,"asset_id")!=str(tr,"asset_id"){cross=false;add(&es,"RIGHTS_ASSET_MISMATCH")};if str(r,"claimant_entity_id")!=str(l,"grantor_entity_id"){cross=false;add(&es,"RIGHTS_CLAIMANT_MISMATCH")}
  if str(l,"asset_id")!=str(tr,"asset_id")||str(l,"grantor_entity_id")!=str(tr,"grantor_entity_id")||str(l,"licensee_entity_id")!=str(tr,"licensee_entity_id")||str(l,"rights_claim_id")!=str(r,"claim_id"){cross=false;add(&es,"LICENCE_LINK_MISMATCH")}
  if str(u,"licence_id")!=str(l,"licence_id")||str(u,"asset_id")!=str(tr,"asset_id")||str(u,"user_entity_id")!=str(l,"licensee_entity_id"){cross=false;add(&es,"USAGE_LINK_MISMATCH")};if str(u,"purpose")!=str(l,"authorized_purpose"){cross=false;add(&es,"USAGE_PURPOSE_UNAUTHORIZED")}
  if str(s,"licence_id")!=str(l,"licence_id"){cross=false;add(&es,"SETTLEMENT_LINK_MISMATCH")};if str(s,"payer_entity_id")!=str(l,"licensee_entity_id")||str(s,"payee_entity_id")!=str(l,"grantor_entity_id"){cross=false;add(&es,"SETTLEMENT_DIRECTION_INVALID")}
  if boolean(v,"realized_external")&&(str(v,"settlement_id")!=str(s,"settlement_id")||!boolean(s,"verified_external")||num(v,"amount_minor")>num(s,"amount_minor")){cross=false;add(&es,"VALUE_EXCEEDS_SETTLEMENT")}
  if str(d,"asset_id")!=str(tr,"asset_id")||str(d,"usage_id")!=str(u,"usage_id")||str(d,"licence_id")!=str(l,"licence_id")||str(d,"settlement_id")!=str(s,"settlement_id"){cross=false;add(&es,"COMMODITY_LINK_MISMATCH")};if num(d,"contribution_minor")>num(s,"amount_minor"){cross=false;add(&es,"COMMODITY_EXCEEDS_SETTLEMENT")}
  if str(ca,"share_class_id")!=str(c,"share_class_id")||str(ca,"issuance_request_id")!=str(c,"issuance_request_id"){cross=false;add(&es,"CAPITAL_AUTH_MISMATCH")};if num(obj(c["accounting"]),"debit_minor")!=num(obj(c["accounting"]),"credit_minor"){cross=false;add(&es,"CAPITAL_ACCOUNTING_UNBALANCED")}
  var pos int64;if a,ok:=c["positions"].([]any);ok{for _,x:=range a{pos+=num(x,"shares")}};if num(c,"outstanding_before")+num(c,"shares_issued")!=num(c,"outstanding_after")||pos!=num(c,"outstanding_after"){cross=false;add(&es,"CAPITAL_SHARES_UNRECONCILED")};if str(ss,"capital_event_id")!=str(c,"capital_event_id"){cross=false;add(&es,"SHARE_SETTLEMENT_LINK_MISMATCH")}
 } else {cross=false}
 ledgerOk:=false;if reqOk{ledgerOk=verifyLedger(ev["event_ledger"],&es)};sort.Strings(es);overall:=rootOk&&sigOk&&reqOk&&cross&&ledgerOk&&len(es)==0
 return map[string]any{"schema":"entity-cleanroom-verification-result-v1","transaction_id":str(b,"transaction_id"),"transaction_root_sha256":str(b,"transaction_root_sha256"),"root_valid":rootOk,"signature_valid":sigOk,"required_sections_valid":reqOk,"cross_links_valid":cross,"ledger_valid":ledgerOk,"overall_valid":overall,"error_codes":es}
}
func resultHash(r any) string{return shaText(canon(r))}
func verifyRecovery(dir,keyFile string) map[string]any {
 m:=obj(load(filepath.Join(dir,"RECOVERY_MANIFEST.json")));bundle,_:=os.ReadFile(filepath.Join(dir,"TRANSACTION_BUNDLE.json"));enc,_:=os.ReadFile(filepath.Join(dir,"STATE_BACKUP.enc"));kh,_:=os.ReadFile(keyFile);key,_:=hex.DecodeString(string(bytes.TrimSpace(kh)))
 unsigned:=map[string]any{};for k,v:=range m{if k!="signature"{unsigned[k]=v}};s:=obj(m["signature"]);sigOk:=false
 if der,e:=base64.StdEncoding.DecodeString(str(s,"public_key_spki_der_b64"));e==nil{if k,e:=x509.ParsePKIXPublicKey(der);e==nil{if pk,ok:=k.(ed25519.PublicKey);ok{if sg,e:=base64.StdEncoding.DecodeString(str(s,"sig_b64"));e==nil{sigOk=ed25519.Verify(pk,[]byte(canon(unsigned)),sg)}}}}
 hashes:=shaBytes(bundle)==str(m,"transaction_bundle_sha256")&&shaBytes(enc)==str(m,"encrypted_state_sha256")&&shaBytes(key)==str(m,"recovery_key_fingerprint_sha256")
 nonce,_:=base64.StdEncoding.DecodeString(str(m,"nonce_b64"));block,_:=aes.NewCipher(key);var gcm cipher.AEAD;gcm,_=cipher.NewGCMWithTagSize(block,int(num(m,"tag_bytes")));plain,e:=gcm.Open(nil,nonce,enc,nil);dec:=e==nil;restored:=""
 if dec{state:=obj(parse(plain));restored=shaText(canon(state["evidence"]))};ok:=sigOk&&hashes&&dec&&restored==str(m,"transaction_root_sha256")
 return map[string]any{"schema":"entity-cleanroom-recovery-result-v1","signature_valid":sigOk,"hashes_valid":hashes,"decrypt_valid":dec,"restored_transaction_root_sha256":restored,"expected_transaction_root_sha256":str(m,"transaction_root_sha256"),"overall_valid":ok}
}
func main(){
 cwd,_:=os.Getwd();kit:=filepath.Join(cwd,"conformance-kit");args:=os.Args[1:]
 if len(args)>0&&args[0]!="test"{r:=verifyBundle(load(args[0]));out:=map[string]any{"result_sha256":resultHash(r),"result":r};b,_:=json.Marshal(out);fmt.Println(string(b));if !r["overall_valid"].(bool){os.Exit(1)};return}
 manifest:=obj(load(filepath.Join(kit,"vectors","VECTOR_MANIFEST.json")));vecs:=manifest["vectors"].([]any);rows:=[]any{};passed:=0
 for _,vv:=range vecs{v:=obj(vv);r:=verifyBundle(load(filepath.Join(kit,"vectors",str(v,"file"))));exp:=obj(v["expected"]);rb,_:=json.Marshal(r["error_codes"]);eb,_:=json.Marshal(exp["error_codes"]);ok:=r["overall_valid"]==exp["overall_valid"]&&bytes.Equal(rb,eb);if ok{passed++};rows=append(rows,map[string]any{"name":str(v,"name"),"ok":ok,"result_sha256":resultHash(r),"result":r})}
 rec:=verifyRecovery(filepath.Join(kit,"vectors","recovery"),filepath.Join(kit,"vectors","test_inputs","recovery_key.hex"));glob:=runGlobalCampaign(filepath.Join(cwd,"global-conformance-kit"));report:=map[string]any{"implementation":"go","vectors_passed":passed,"vectors_total":len(vecs),"recovery_pass":rec["overall_valid"],"golden_root":manifest["valid_transaction_root_sha256"],"results":rows,"recovery":rec,"global_v3_1":glob};b,_:=json.MarshalIndent(report,"","  ");fmt.Println(string(b));if passed!=len(vecs)||rec["overall_valid"]!=true||glob["overall_valid"]!=true{os.Exit(1)}
}
