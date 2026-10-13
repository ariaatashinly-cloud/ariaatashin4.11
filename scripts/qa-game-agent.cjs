// Controlled desktop companion UI check. Requires Playwright, openssl and a
// compatible sing-box with Clash API. No commercial game or external account.
const {chromium}=require('playwright');
const fs=require('fs'),os=require('os'),path=require('path'),https=require('https'),http=require('http'),net=require('net');
const {spawn,execFileSync}=require('child_process');
const source=path.resolve(__dirname,'..'),dir=fs.mkdtempSync(path.join(os.tmpdir(),'aria-agent-qa-'));
const agentBin=process.env.ARIA_TEST_AGENT||path.join(source,'web/game-agent/game-route-agent-linux-amd64');
const engine=process.env.ARIA_TEST_SING_BOX;
if(!engine)throw Error('Set ARIA_TEST_SING_BOX to a compatible Clash API engine');
const key=path.join(dir,'key.pem'),cert=path.join(dir,'cert.pem');
execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-subj','/CN=localhost','-addext','subjectAltName=IP:127.0.0.1,DNS:localhost','-days','1'],{stdio:'ignore'});
let reports=[],connections=0,child,browser;
const fixture=https.createServer({key:fs.readFileSync(key),cert:fs.readFileSync(cert)},(req,res)=>{if(req.url==='/report'){const chunks=[];req.on('data',c=>chunks.push(c));req.on('end',()=>{reports.push(JSON.parse(Buffer.concat(chunks)));res.writeHead(200,{'content-type':'application/json'});res.end('{"ok":true}')});return}res.writeHead(204);res.end()});
const proxy=http.createServer();proxy.on('connect',(req,socket,head)=>{const [host,p]=req.url.split(':');if(host!=='127.0.0.1'||+p!==fixture.address().port){socket.end('HTTP/1.1 403 Forbidden\r\n\r\n');return}connections++;const upstream=net.connect(+p,host,()=>{socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');if(head.length)upstream.write(head);socket.pipe(upstream);upstream.pipe(socket)});upstream.on('error',()=>socket.destroy());socket.on('error',()=>upstream.destroy())});
async function main(){
 await new Promise(r=>fixture.listen(0,'127.0.0.1',r));await new Promise(r=>proxy.listen(0,'127.0.0.1',r));
 const base='https://127.0.0.1:'+fixture.address().port;
 const job={version:1,id:'gt-local-browser48',gameID:'rainbow-six',gameName:'آزمون محلی رینبو سیکس',mode:'full',expires:Math.floor(Date.now()/1000)+3600,reportURL:base+'/report',reportToken:'c'.repeat(64),targets:[{name:'Local TLS fixture',url:base+'/'}],autoService:true,config:{log:{level:'warn'},dns:{servers:[{type:'local',tag:'bootstrap'},{type:'https',tag:'personal',server:'cloudflare-dns.com',server_port:443,path:'/dns-query',tls:{enabled:true,server_name:'cloudflare-dns.com'},domain_resolver:'bootstrap',detour:'game-route'}],final:'personal',strategy:'ipv4_only'},inbounds:[{type:'tun',tag:'game-tun',address:['172.19.0.1/30'],auto_route:true,stack:'system'}],outbounds:[{type:'http',tag:'game-proxy',server:'127.0.0.1',server_port:proxy.address().port},{type:'direct',tag:'direct',domain_resolver:'bootstrap'},{type:'selector',tag:'game-route',outbounds:['game-proxy'],default:'game-proxy',interrupt_exist_connections:false}],route:{auto_detect_interface:true,default_domain_resolver:'personal',rules:[{ip_is_private:true,action:'route',outbound:'direct'}],final:'game-route'}}};
 const jobFile=path.join(dir,'job.json');fs.writeFileSync(jobFile,JSON.stringify(job),{mode:0o600});fs.chmodSync(agentBin,0o700);
 child=spawn(agentBin,['--job',jobFile,'--sing-box',engine],{env:{...process.env,SSL_CERT_FILE:cert},stdio:['ignore','pipe','pipe']});let output='';child.stdout.on('data',b=>output+=b);let stderr='';child.stderr.on('data',b=>stderr+=b);
 let localURL;for(let i=0;i<150;i++){const m=output.match(/Open on this computer: (http:\/\/127\.0\.0\.1:\d+\/#\w+)/);if(m){localURL=m[1];break}if(child.exitCode!==null)throw Error('agent exited: '+stderr);await new Promise(r=>setTimeout(r,100))}if(!localURL)throw Error('local UI did not start: '+stderr);
 browser=await chromium.launch({headless:true,executablePath:process.env.ARIA_TEST_CHROMIUM,args:['--no-sandbox']});const page=await browser.newPage({viewport:{width:1120,height:900}}),errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto(localURL);await page.locator('#result').getByText('سرویس از هر دو مسیر پاسخ داد',{exact:false}).waitFor();await page.getByRole('button',{name:'امتحان بازی با پروکسی'}).click();await page.locator('#result').getByText('مسیر انتخابی: پروکسی',{exact:false}).waitFor();
 await page.reload();await page.locator('#result').getByText('مسیر انتخابی: پروکسی',{exact:false}).waitFor();if(!await page.getByRole('button',{name:'ورود و مسابقه موفق شد'}).isDisabled())throw Error('gameplay confirmation enabled in probe-only mode');
 await page.setViewportSize({width:390,height:844});const overflow=await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth);if(overflow)throw Error('local dashboard mobile overflow');
 if(process.env.ARIA_TEST_SCREENSHOT)await page.screenshot({path:process.env.ARIA_TEST_SCREENSHOT,fullPage:true});
 const result={errors,localDashboard:true,independentProxyRequests:connections>2,panelReportSent:reports.length>0,realSelectorChanged:true,reloadKeepsLocalAccess:true,probeOnlyCannotConfirmGameplay:true,mobileOverflow:overflow};console.log(JSON.stringify(result));if(errors.length)throw Error('JavaScript errors');
}
main().catch(e=>{console.error(e.stack);process.exitCode=1}).finally(async()=>{if(browser)await browser.close();if(child)child.kill('SIGTERM');fixture.close();proxy.close();fs.rmSync(dir,{recursive:true,force:true})});
