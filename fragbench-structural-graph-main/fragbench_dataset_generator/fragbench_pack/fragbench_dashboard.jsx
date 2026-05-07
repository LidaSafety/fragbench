import { useState, useMemo } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Legend, Treemap } from "recharts";

const DATA = {"campaigns":[{"id":"INC-001","name":"GTG-1002 Espionage","source":"Anthropic","category":"confirmed","n_tasks":6,"n_prompts":29,"frag_range":[12,30],"mitre_tactics":["Collection","Command and Control","Credential Access","Initial Access","Reconnaissance"],"tasks":[{"name":"Reconnaissance: Campaign init and target selection","mitre":"Reconnaissance","mitre_id":"T1595","n_prompts":4,"frag_range":[2,4]},{"name":"Reconnaissance: Attack-surface mapping","mitre":"Reconnaissance","mitre_id":"T1595","n_prompts":7,"frag_range":[3,8]},{"name":"Initial Access: Vulnerability discovery and exploit d","mitre":"Initial Access","mitre_id":"T1190","n_prompts":5,"frag_range":[2,5]},{"name":"Credential Access / Lateral Movement: Credential harv","mitre":"Credential Access","mitre_id":"T1552","n_prompts":5,"frag_range":[2,5]},{"name":"Collection / Exfiltration: Data collection","mitre":"Collection","mitre_id":"T1005","n_prompts":5,"frag_range":[2,5]},{"name":"Persistence: Documentation and handoff","mitre":"Command and Control","mitre_id":"T1071","n_prompts":3,"frag_range":[1,3]}]},{"id":"INC-002","name":"GTG-2002 Extortion","source":"Anthropic","category":"confirmed","n_tasks":5,"n_prompts":22,"frag_range":[10,23],"mitre_tactics":["Credential Access","Defense Evasion","Exfiltration","Impact","Reconnaissance"],"tasks":[{"name":"Reconnaissance: Target discovery","mitre":"Reconnaissance","mitre_id":"T1595","n_prompts":4,"frag_range":[2,5]},{"name":"Credential Access: AD attacks","mitre":"Credential Access","mitre_id":"T1558","n_prompts":4,"frag_range":[2,5]},{"name":"Defense Evasion: Malware obfuscation","mitre":"Defense Evasion","mitre_id":"T1027","n_prompts":5,"frag_range":[2,5]},{"name":"Exfiltration: Data exfil and analysis","mitre":"Exfiltration","mitre_id":"T1041","n_prompts":4,"frag_range":[2,4]},{"name":"Impact: Ransom note creation","mitre":"Impact","mitre_id":"T1486","n_prompts":4,"frag_range":[2,4]}]},{"id":"INC-003","name":"AI RaaS Developer","source":"Anthropic","category":"confirmed","n_tasks":6,"n_prompts":25,"frag_range":[13,26],"mitre_tactics":["Defense Evasion","Impact","Resource Development"],"tasks":[{"name":"Resource Development: RaaS product","mitre":"Resource Development","mitre_id":"T1587.001","n_prompts":6,"frag_range":[3,7]},{"name":"Defense Evasion: Anti-analysis","mitre":"Defense Evasion","mitre_id":"T1106","n_prompts":4,"frag_range":[2,4]},{"name":"Impact: File encryption","mitre":"Impact","mitre_id":"T1486","n_prompts":3,"frag_range":[2,4]},{"name":"Delivery: DLL injection","mitre":"Defense Evasion","mitre_id":"T1055.001","n_prompts":3,"frag_range":[2,4]},{"name":"Anti-recovery: Shadow copy deletion","mitre":"Impact","mitre_id":"T1490","n_prompts":2,"frag_range":[1,3]},{"name":"Resource Development: RaaS packaging","mitre":"Resource Development","mitre_id":"T1587.001","n_prompts":4,"frag_range":[2,4]}]},{"id":"INC-004","name":"DPRK IT Fraud","source":"Anthropic","category":"confirmed","n_tasks":5,"n_prompts":28,"frag_range":[13,33],"mitre_tactics":["Impact","Initial Access","Persistence","Reconnaissance","Resource Development"],"tasks":[{"name":"Resource Development: False persona","mitre":"Resource Development","mitre_id":"T1585.001","n_prompts":5,"frag_range":[2,5]},{"name":"Reconnaissance: Job market analysis","mitre":"Reconnaissance","mitre_id":"T1593","n_prompts":4,"frag_range":[2,4]},{"name":"Initial Access: Interview process","mitre":"Initial Access","mitre_id":"T1566","n_prompts":7,"frag_range":[3,8]},{"name":"Persistence: Employment maintenance","mitre":"Persistence","mitre_id":"T1078","n_prompts":12,"frag_range":[4,12]},{"name":"Impact: Revenue generation","mitre":"Impact","mitre_id":"T1657","n_prompts":2,"frag_range":[1,2]}]},{"id":"INC-005","name":"China vs Vietnam","source":"Anthropic","category":"confirmed","n_tasks":7,"n_prompts":24,"frag_range":[12,27],"mitre_tactics":["Collection","Command and Control","Credential Access","Initial Access","Privilege Escalation","Reconnaissance","Resource Development"],"tasks":[{"name":"Resource Development: Campaign setup","mitre":"Resource Development","mitre_id":"T1583","n_prompts":2,"frag_range":[1,3]},{"name":"Reconnaissance: IP scanning","mitre":"Reconnaissance","mitre_id":"T1595","n_prompts":4,"frag_range":[2,5]},{"name":"Initial Access: WordPress exploit","mitre":"Initial Access","mitre_id":"T1190","n_prompts":3,"frag_range":[2,4]},{"name":"Credential Access: Hydra/hashcat","mitre":"Credential Access","mitre_id":"T1110","n_prompts":3,"frag_range":[2,4]},{"name":"Priv Escalation: Linux kernel","mitre":"Privilege Escalation","mitre_id":"T1068","n_prompts":2,"frag_range":[1,3]},{"name":"C2: Proxy chains","mitre":"Command and Control","mitre_id":"T1090","n_prompts":2,"frag_range":[1,3]},{"name":"Collection: Intelligence","mitre":"Collection","mitre_id":"T1119","n_prompts":4,"frag_range":[2,5]}]}],
"sources":{"Anthropic":5,"Google GTIG":8,"OpenAI":6,"SentinelLABS":1,"Unit 42 / Palo Alto":1,"Microsoft":6,"CCCS":1,"Public reporting":3,"UnitedHealth":1,"Maine AG":1,"YNHHS":1,"Sophos":1},
"mitre_tactics":{"Reconnaissance":17,"Initial Access":16,"Credential Access":7,"Collection":5,"Command and Control":6,"Defense Evasion":11,"Exfiltration":5,"Impact":10,"Resource Development":26,"Persistence":4,"Privilege Escalation":1,"Execution":5,"Discovery":4,"Lateral Movement":1},
"categories":{"confirmed":27,"hypothetical":8},
"scale_table":[{"size":"100","actual":70,"per_camp":1,"train":0,"test":70},{"size":"100K","actual":99960,"per_camp":1428,"train":79940,"test":20020},{"size":"1M","actual":999950,"per_camp":14285,"train":799960,"test":199990},{"size":"100M","actual":99999970,"per_camp":1428571,"train":79999920,"test":20000050},{"size":"1B","actual":999999980,"per_camp":14285714,"train":799999970,"test":200000010}]};

// Extend with remaining campaigns (abbreviated for size)
const ALL_CAMPS = [
  ...DATA.campaigns,
  {id:"INC-006",name:"PROMPTSTEAL",source:"Google GTIG",category:"confirmed",n_tasks:5,n_prompts:12,frag_range:[7,17],mitre_tactics:["Initial Access","Discovery","Collection","Exfiltration"]},
  {id:"INC-007",name:"PROMPTFLUX",source:"Google GTIG",category:"confirmed",n_tasks:5,n_prompts:16,frag_range:[9,19],mitre_tactics:["Resource Development","Command and Control","Defense Evasion","Persistence","Lateral Movement"]},
  {id:"INC-008",name:"HONESTCUE",source:"Google GTIG",category:"confirmed",n_tasks:5,n_prompts:13,frag_range:[8,16],mitre_tactics:["Resource Development","Command and Control","Execution","Defense Evasion"]},
  {id:"INC-009",name:"QUIETVAULT",source:"Google GTIG",category:"confirmed",n_tasks:4,n_prompts:11,frag_range:[7,14],mitre_tactics:["Execution","Credential Access","Discovery","Exfiltration"]},
  {id:"INC-010",name:"COINBAIT",source:"Google GTIG",category:"confirmed",n_tasks:3,n_prompts:10,frag_range:[5,12],mitre_tactics:["Resource Development","Defense Evasion","Credential Access"]},
  {id:"INC-011",name:"APT42 Phishing",source:"Google GTIG",category:"confirmed",n_tasks:4,n_prompts:12,frag_range:[6,15],mitre_tactics:["Reconnaissance","Initial Access","Resource Development"]},
  {id:"INC-012",name:"UNC2970 Profiling",source:"Google GTIG",category:"confirmed",n_tasks:3,n_prompts:10,frag_range:[5,12],mitre_tactics:["Reconnaissance","Resource Development","Initial Access"]},
  {id:"INC-013",name:"ClickFix AI Chat",source:"Google GTIG",category:"confirmed",n_tasks:3,n_prompts:8,frag_range:[5,11],mitre_tactics:["Resource Development","Initial Access","Execution"]},
  {id:"INC-014",name:"ScopeCreep",source:"OpenAI",category:"confirmed",n_tasks:6,n_prompts:23,frag_range:[12,24],mitre_tactics:["Resource Development","Defense Evasion","Initial Access","Credential Access","Command and Control"]},
  {id:"INC-015",name:"RU Malware",source:"OpenAI",category:"confirmed",n_tasks:3,n_prompts:11,frag_range:[6,13],mitre_tactics:["Resource Development","Defense Evasion","Exfiltration"]},
  {id:"INC-016",name:"MalTerminal",source:"SentinelLABS",category:"confirmed",n_tasks:3,n_prompts:8,frag_range:[5,9],mitre_tactics:["Resource Development","Execution"]},
  {id:"INC-017",name:"WormGPT",source:"Unit 42",category:"confirmed",n_tasks:4,n_prompts:14,frag_range:[8,16],mitre_tactics:["Resource Development","Initial Access","Impact"]},
  {id:"INC-018",name:"AI Phishing Stats",source:"Microsoft",category:"confirmed",n_tasks:3,n_prompts:9,frag_range:[5,12],mitre_tactics:["Resource Development","Initial Access","Impact"]},
  {id:"INC-019",name:"Deepfake Fraud",source:"Microsoft",category:"confirmed",n_tasks:3,n_prompts:8,frag_range:[5,11],mitre_tactics:["Resource Development","Initial Access","Impact"]},
  {id:"INC-020",name:"Op. Trolling Stone",source:"OpenAI",category:"confirmed",n_tasks:3,n_prompts:10,frag_range:[5,11],mitre_tactics:["Reconnaissance","Resource Development"]},
  {id:"INC-021",name:"Op. No Bell",source:"OpenAI",category:"confirmed",n_tasks:3,n_prompts:12,frag_range:[6,13],mitre_tactics:["Resource Development"]},
  {id:"INC-022",name:"Op. Date Bait",source:"OpenAI",category:"confirmed",n_tasks:3,n_prompts:9,frag_range:[5,12],mitre_tactics:["Resource Development","Initial Access","Impact"]},
  {id:"INC-023",name:"Op. False Witness",source:"OpenAI",category:"confirmed",n_tasks:4,n_prompts:12,frag_range:[7,14],mitre_tactics:["Resource Development","Initial Access","Impact"]},
  {id:"INC-024",name:"Coral Sleet",source:"Microsoft",category:"confirmed",n_tasks:3,n_prompts:9,frag_range:[5,12],mitre_tactics:["Resource Development"]},
  {id:"INC-025",name:"Emerald Sleet",source:"Microsoft",category:"confirmed",n_tasks:3,n_prompts:10,frag_range:[6,12],mitre_tactics:["Reconnaissance","Initial Access"]},
  {id:"INC-026",name:"Jasper Sleet",source:"Microsoft",category:"confirmed",n_tasks:6,n_prompts:21,frag_range:[11,24],mitre_tactics:["Resource Development","Reconnaissance","Defense Evasion","Command and Control","Persistence"]},
  {id:"INC-027",name:"Tycoon2FA",source:"Microsoft",category:"confirmed",n_tasks:6,n_prompts:19,frag_range:[11,23],mitre_tactics:["Resource Development","Initial Access","Defense Evasion","Credential Access","Exfiltration","Persistence"]},
  {id:"INC-028",name:"Nova Scotia Power",source:"CCCS",category:"hypothetical",n_tasks:3,n_prompts:10,frag_range:[6,13],mitre_tactics:["Reconnaissance","Persistence","Collection"]},
  {id:"INC-029",name:"London Drugs/LockBit",source:"Public",category:"hypothetical",n_tasks:3,n_prompts:9,frag_range:[6,12],mitre_tactics:["Initial Access","Lateral Movement","Impact"]},
  {id:"INC-030",name:"Change Healthcare",source:"UnitedHealth",category:"hypothetical",n_tasks:3,n_prompts:11,frag_range:[6,14],mitre_tactics:["Credential Access","Lateral Movement","Exfiltration"]},
  {id:"INC-031",name:"Covenant Health",source:"Maine AG",category:"hypothetical",n_tasks:2,n_prompts:7,frag_range:[4,8],mitre_tactics:["Initial Access","Collection"]},
  {id:"INC-032",name:"St. Paul MN",source:"Public",category:"hypothetical",n_tasks:3,n_prompts:9,frag_range:[6,12],mitre_tactics:["Initial Access","Persistence","Exfiltration"]},
  {id:"INC-033",name:"M&S+Co-op+Harrods",source:"Public",category:"hypothetical",n_tasks:3,n_prompts:11,frag_range:[6,13],mitre_tactics:["Initial Access","Credential Access","Impact"]},
  {id:"INC-034",name:"Yale New Haven",source:"YNHHS",category:"hypothetical",n_tasks:2,n_prompts:7,frag_range:[4,9],mitre_tactics:["Discovery","Collection"]},
  {id:"INC-035",name:"RedCurl/Gold Blade",source:"Sophos",category:"hypothetical",n_tasks:3,n_prompts:9,frag_range:[6,12],mitre_tactics:["Initial Access","Collection","Impact"]},
];

const COLORS = ["#3B82F6","#EF4444","#10B981","#F59E0B","#8B5CF6","#EC4899","#06B6D4","#F97316","#6366F1","#14B8A6","#E11D48","#84CC16","#A855F7","#0EA5E9"];
const SRC_COLORS = {"Anthropic":"#D97706","Google GTIG":"#2563EB","OpenAI":"#059669","Microsoft":"#7C3AED","SentinelLABS":"#DC2626","Unit 42":"#DB2777","CCCS":"#0891B2","Public":"#64748B","UnitedHealth":"#4F46E5","Maine AG":"#0D9488","YNHHS":"#9333EA","Sophos":"#E11D48"};

export default function Dashboard() {
  const [selectedCamp, setSelectedCamp] = useState(null);
  const [view, setView] = useState("overview");

  const sourceData = useMemo(() =>
    Object.entries(DATA.sources).map(([k,v]) => ({name:k,value:v})).sort((a,b)=>b.value-a.value), []);

  const mitreData = useMemo(() =>
    Object.entries(DATA.mitre_tactics).map(([k,v]) => ({name:k.replace(/ /g,'\n'),fullName:k,value:v})).sort((a,b)=>b.value-a.value), []);

  const scaleData = DATA.scale_table;

  const tasksBySource = useMemo(() => {
    const m = {};
    ALL_CAMPS.forEach(c => {
      const s = c.source.split(" ")[0]; // short name
      m[s] = (m[s]||0) + c.n_tasks;
    });
    return Object.entries(m).map(([k,v])=>({name:k,tasks:v}));
  }, []);

  const campsByTasks = useMemo(() =>
    ALL_CAMPS.map(c => ({
      name: c.id.replace("INC-0","").replace("INC-",""),
      fullName: c.name,
      tasks: c.n_tasks,
      prompts: c.n_prompts,
      fragMin: c.frag_range[0],
      fragMax: c.frag_range[1],
      source: c.source,
      cat: c.category,
    })), []);

  const camp = selectedCamp ? ALL_CAMPS.find(c=>c.id===selectedCamp) : null;

  return (
    <div className="min-h-screen p-4" style={{fontFamily:"system-ui",maxWidth:1100,margin:"0 auto"}}>
      <div className="mb-6">
        <h1 className="text-2xl font-bold mb-1">FragBench Dataset Dashboard</h1>
        <p className="text-sm text-gray-500">35 campaigns · 476 base prompts · scalable to 1B samples</p>
      </div>

      {/* Nav */}
      <div className="flex gap-2 mb-6 flex-wrap">
        {["overview","campaigns","mitre","scale"].map(v => (
          <button key={v} onClick={()=>setView(v)}
            className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${view===v ? "bg-blue-600 text-white" : "bg-gray-100 text-gray-700 hover:bg-gray-200"}`}>
            {v==="overview"?"Overview":v==="campaigns"?"Campaigns":v==="mitre"?"MITRE ATT&CK":"Scale"}
          </button>
        ))}
      </div>

      {view === "overview" && (
        <div>
          {/* Summary cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
            {[
              {label:"Campaigns",val:"35",sub:"27 confirmed + 8 hypothetical"},
              {label:"Base Prompts",val:"476",sub:"× variation = unlimited"},
              {label:"Tasks Total",val:ALL_CAMPS.reduce((s,c)=>s+c.n_tasks,0),sub:"across all campaigns"},
              {label:"MITRE Tactics",val:Object.keys(DATA.mitre_tactics).length,sub:"unique ATT&CK tactics"},
            ].map(({label,val,sub}) => (
              <div key={label} className="bg-gray-50 rounded-xl p-4">
                <div className="text-xs text-gray-500">{label}</div>
                <div className="text-2xl font-bold mt-1">{val}</div>
                <div className="text-xs text-gray-400 mt-1">{sub}</div>
              </div>
            ))}
          </div>

          {/* Source distribution */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
            <div className="bg-gray-50 rounded-xl p-4">
              <h3 className="text-sm font-semibold mb-3">Campaigns by Intelligence Source</h3>
              <ResponsiveContainer width="100%" height={220}>
                <PieChart>
                  <Pie data={sourceData} cx="50%" cy="50%" outerRadius={80} dataKey="value" label={({name,value})=>`${name} (${value})`} labelLine={false} fontSize={10}>
                    {sourceData.map((_,i) => <Cell key={i} fill={COLORS[i%COLORS.length]} />)}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="bg-gray-50 rounded-xl p-4">
              <h3 className="text-sm font-semibold mb-3">Confirmed vs Hypothetical</h3>
              <ResponsiveContainer width="100%" height={220}>
                <PieChart>
                  <Pie data={[{name:"Confirmed",value:27},{name:"Hypothetical",value:8}]} cx="50%" cy="50%" outerRadius={80} dataKey="value" label={({name,value})=>`${name}: ${value}`}>
                    <Cell fill="#3B82F6" /><Cell fill="#F59E0B" />
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Prompts & fragments per campaign */}
          <div className="bg-gray-50 rounded-xl p-4 mb-6">
            <h3 className="text-sm font-semibold mb-3">Prompts per Campaign (base pool, before variation)</h3>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={campsByTasks} margin={{bottom:60}}>
                <XAxis dataKey="name" angle={-45} textAnchor="end" fontSize={10} interval={0} height={60} />
                <YAxis fontSize={11} />
                <Tooltip content={({payload})=>{
                  if(!payload?.length) return null;
                  const d=payload[0].payload;
                  return <div className="bg-white p-2 rounded shadow text-xs border">
                    <div className="font-bold">{d.fullName}</div>
                    <div>Source: {d.source}</div>
                    <div>Tasks: {d.tasks} · Prompts: {d.prompts}</div>
                    <div>Fragments/sample: {d.fragMin}–{d.fragMax}</div>
                  </div>;
                }} />
                <Bar dataKey="prompts" fill="#3B82F6" radius={[3,3,0,0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Fragment ranges */}
          <div className="bg-gray-50 rounded-xl p-4">
            <h3 className="text-sm font-semibold mb-3">Attack Fragments per Sample (min–max range)</h3>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={campsByTasks} margin={{bottom:60}}>
                <XAxis dataKey="name" angle={-45} textAnchor="end" fontSize={10} interval={0} height={60} />
                <YAxis fontSize={11} />
                <Tooltip content={({payload})=>{
                  if(!payload?.length) return null;
                  const d=payload[0].payload;
                  return <div className="bg-white p-2 rounded shadow text-xs border">
                    <div className="font-bold">{d.fullName}</div>
                    <div>Fragment range: {d.fragMin}–{d.fragMax}</div>
                    <div>Tasks: {d.tasks}</div>
                  </div>;
                }} />
                <Bar dataKey="fragMin" fill="#93C5FD" name="Min frags" stackId="a" radius={[0,0,0,0]} />
                <Bar dataKey="fragMax" fill="#2563EB" name="Max frags" radius={[3,3,0,0]} />
                <Legend fontSize={11} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {view === "campaigns" && (
        <div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 mb-4">
            {ALL_CAMPS.map(c => (
              <button key={c.id} onClick={()=>setSelectedCamp(selectedCamp===c.id?null:c.id)}
                className={`text-left p-3 rounded-xl border transition-all ${selectedCamp===c.id?"border-blue-500 bg-blue-50":"border-gray-200 bg-white hover:border-gray-300"}`}>
                <div className="flex items-center gap-2 mb-1">
                  <span className={`w-2 h-2 rounded-full ${c.category==="confirmed"?"bg-blue-500":"bg-amber-500"}`} />
                  <span className="text-xs font-mono text-gray-400">{c.id}</span>
                </div>
                <div className="font-medium text-sm">{c.name}</div>
                <div className="text-xs text-gray-500 mt-1">{c.source} · {c.n_tasks} tasks · {c.n_prompts} prompts</div>
                <div className="flex gap-1 mt-2 flex-wrap">
                  {c.mitre_tactics.slice(0,3).map(t => (
                    <span key={t} className="text-[10px] px-1.5 py-0.5 rounded bg-gray-100 text-gray-600">{t}</span>
                  ))}
                  {c.mitre_tactics.length > 3 && <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-100 text-gray-400">+{c.mitre_tactics.length-3}</span>}
                </div>
              </button>
            ))}
          </div>

          {camp && (
            <div className="bg-gray-50 rounded-xl p-4 mt-4">
              <h3 className="font-semibold mb-1">{camp.id}: {camp.name}</h3>
              <p className="text-xs text-gray-500 mb-3">{camp.source} · {camp.category} · {camp.n_tasks} tasks · {camp.n_prompts} prompts · {camp.frag_range[0]}–{camp.frag_range[1]} fragments/sample</p>
              {camp.tasks ? (
                <div className="space-y-2">
                  {camp.tasks.map((t,i) => (
                    <div key={i} className="bg-white rounded-lg p-3 border border-gray-200">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-xs font-mono bg-blue-100 text-blue-700 px-1.5 py-0.5 rounded">{t.mitre_id}</span>
                        <span className="text-xs text-gray-400">{t.mitre}</span>
                      </div>
                      <div className="text-sm font-medium">{t.name}</div>
                      <div className="text-xs text-gray-500 mt-1">{t.n_prompts} prompts · {t.frag_range[0]}–{t.frag_range[1]} fragments</div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-xs text-gray-400">Task detail available for first 5 campaigns. Click source campaigns for full breakdown.</div>
              )}
            </div>
          )}
        </div>
      )}

      {view === "mitre" && (
        <div>
          <div className="bg-gray-50 rounded-xl p-4 mb-6">
            <h3 className="text-sm font-semibold mb-3">MITRE ATT&CK Tactic Distribution (tasks using each tactic)</h3>
            <ResponsiveContainer width="100%" height={350}>
              <BarChart data={mitreData} layout="vertical" margin={{left:120}}>
                <XAxis type="number" fontSize={11} />
                <YAxis type="category" dataKey="fullName" fontSize={11} width={120} />
                <Tooltip />
                <Bar dataKey="value" fill="#6366F1" radius={[0,4,4,0]} name="Tasks" />
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="bg-gray-50 rounded-xl p-4">
            <h3 className="text-sm font-semibold mb-3">Tactics per Campaign</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b">
                    <th className="text-left py-2 pr-2">Campaign</th>
                    <th className="text-left py-2 pr-2">Source</th>
                    <th className="text-center py-2">#Tactics</th>
                    <th className="text-left py-2 pl-2">Tactics</th>
                  </tr>
                </thead>
                <tbody>
                  {ALL_CAMPS.sort((a,b)=>b.mitre_tactics.length-a.mitre_tactics.length).map(c => (
                    <tr key={c.id} className="border-b border-gray-100">
                      <td className="py-1.5 pr-2 font-medium">{c.name}</td>
                      <td className="py-1.5 pr-2 text-gray-500">{c.source}</td>
                      <td className="py-1.5 text-center font-mono">{c.mitre_tactics.length}</td>
                      <td className="py-1.5 pl-2">
                        <div className="flex gap-1 flex-wrap">
                          {c.mitre_tactics.map(t => (
                            <span key={t} className="px-1.5 py-0.5 rounded bg-indigo-50 text-indigo-700">{t}</span>
                          ))}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {view === "scale" && (
        <div>
          <div className="bg-gray-50 rounded-xl p-4 mb-6">
            <h3 className="text-sm font-semibold mb-3">Dataset Scaling (balanced: equal samples per campaign per class)</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left">
                    <th className="py-2 pr-4">Target Size</th>
                    <th className="py-2 pr-4">Actual</th>
                    <th className="py-2 pr-4">Per Camp/Class</th>
                    <th className="py-2 pr-4">Train</th>
                    <th className="py-2 pr-4">Test</th>
                    <th className="py-2">Est. File Size</th>
                  </tr>
                </thead>
                <tbody>
                  {scaleData.map(r => (
                    <tr key={r.size} className="border-b border-gray-100">
                      <td className="py-2 pr-4 font-bold">{r.size}</td>
                      <td className="py-2 pr-4 font-mono">{r.actual.toLocaleString()}</td>
                      <td className="py-2 pr-4 font-mono">{r.per_camp.toLocaleString()}</td>
                      <td className="py-2 pr-4 font-mono">{r.train.toLocaleString()}</td>
                      <td className="py-2 pr-4 font-mono">{r.test.toLocaleString()}</td>
                      <td className="py-2 font-mono text-gray-500">
                        {r.actual < 1000 ? "< 1 MB" :
                         r.actual < 1e6 ? `~${Math.round(r.actual*5.5/1e6)} MB` :
                         r.actual < 1e9 ? `~${Math.round(r.actual*5.5/1e9)} GB` :
                         `~${Math.round(r.actual*5.5/1e12*10)/10} TB`}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="bg-gray-50 rounded-xl p-4 mb-6">
            <h3 className="text-sm font-semibold mb-3">Samples per Campaign at Each Scale</h3>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={scaleData}>
                <XAxis dataKey="size" fontSize={12} />
                <YAxis fontSize={11} scale="log" domain={[1,'auto']} tickFormatter={v=>v>=1e6?`${v/1e6}M`:v>=1e3?`${v/1e3}K`:v} />
                <Tooltip formatter={v=>v.toLocaleString()} />
                <Bar dataKey="per_camp" fill="#8B5CF6" radius={[4,4,0,0]} name="Per campaign per class" />
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="bg-amber-50 rounded-xl p-4 border border-amber-200">
            <h3 className="text-sm font-semibold text-amber-800 mb-2">Diversity at Scale</h3>
            <ul className="text-xs text-amber-700 space-y-1">
              <li>• <strong>476 base prompts</strong> × verb/language/detail variations = effectively unlimited unique prompts</li>
              <li>• Each sample draws a random subset with random variations — no two samples are identical</li>
              <li>• Campaign-specific prompts are sampled at 20-40% rate, mixed with universal pool</li>
              <li>• Fragment counts follow log-normal distribution (mean ~24, range 10–475)</li>
              <li>• At 1B: 14.3M samples per campaign per class, each uniquely varied</li>
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}
