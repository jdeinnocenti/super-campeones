import { useState, useEffect, useCallback } from "react";

// ============================================================
// SECURITY — OWASP Top 10
// ============================================================
const Security = {
  sanitize: (v) => {
    if (typeof v !== "string") return "";
    return v.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
            .replace(/"/g,"&quot;").replace(/'/g,"&#x27;").replace(/\//g,"&#x2F;").slice(0,300);
  },
  generateToken: (uid) => {
    const p={userId:uid,exp:Date.now()+3600000,iat:Date.now()};
    return btoa(JSON.stringify(p))+"."+Math.random().toString(36).slice(2);
  },
  validateToken: (tok) => {
    try { const p=JSON.parse(atob(tok.split(".")[0])); return p.exp>Date.now()?p:null; }
    catch { return null; }
  },
  validateScore: (s) => { const n=parseInt(s); return !isNaN(n)&&n>=0&&n<=30; },
  validateUsername: (u) => /^[a-zA-Z0-9_]{3,20}$/.test(u),
  validatePassword: (p) => typeof p==="string"&&p.length>=4&&p.length<=50,
  hashPassword: async (pwd) => {
    const enc = new TextEncoder().encode(pwd + "sc_salt_2024");
    const buf = await crypto.subtle.digest("SHA-256", enc);
    return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,"0")).join("");
  },
  _rl:{},
  rateLimit:(key,max=5,ms=60000)=>{
    const now=Date.now();
    Security._rl[key]=(Security._rl[key]||[]).filter(t=>now-t<ms);
    if(Security._rl[key].length>=max) return false;
    Security._rl[key].push(now); return true;
  }
};

// ============================================================
// SEED DATA
// ============================================================
const AVATARS=["⚽","🌟","🎯","🏅","🔥","⚡","🦁","🐯","🦊","🐺","🎪","🎭","🎨","🎸","🚀","💎","🌈","🦅","🐉","🏆"];

const makePwdHash = async () => {
  // Pre-computed hashes for demo (admin:admin123, players:player123)
  // Using synchronous fallback for seed since crypto.subtle is async
  return "demo_hash";
};

const SEED_USERS=[
  {id:"u1",username:"admin",  passwordHash:"demo_hash",role:"admin",  avatar:"🏆",active:true, createdAt:"2024-01-01"},
  {id:"u2",username:"diego10",passwordHash:"demo_hash",role:"user",   avatar:"⚽",active:true, createdAt:"2024-01-01"},
  {id:"u3",username:"leo30",  passwordHash:"demo_hash",role:"user",   avatar:"🌟",active:true, createdAt:"2024-01-01"},
  {id:"u4",username:"cr7fan", passwordHash:"demo_hash",role:"user",   avatar:"🎯",active:true, createdAt:"2024-01-01"},
];

const SEED_TOURNAMENTS=[
  {id:"t1",name:"FIFA World Cup 2026",shortName:"World Cup 2026",region:"Global — Canadá, México y USA",
   status:"upcoming",logo:"🌍",startDate:"2026-06-11",endDate:"2026-07-19",
   groups:["A","B","C","D","E","F","G","H","I","J","K","L","R32","R16","QF","SF","3P","FIN"],source:"manual"},
];

// TBD format: "TBD:descripción" — se actualiza automáticamente cuando hay ganadores/perdedores

const SEED_MATCHES_T1=[
  // GRUPO A
  {id:"gA1",tId:"t1",group:"A",homeTeam:"México 🇲🇽",awayTeam:"Sudáfrica 🇿🇦",date:"2026-06-11",time:"15:00",stage:"Grupo A",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gA2",tId:"t1",group:"A",homeTeam:"Corea del Sur 🇰🇷",awayTeam:"TBD:Play-off UEFA D",date:"2026-06-11",time:"22:00",stage:"Grupo A",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gA3",tId:"t1",group:"A",homeTeam:"TBD:Play-off UEFA D",awayTeam:"Sudáfrica 🇿🇦",date:"2026-06-18",time:"18:00",stage:"Grupo A",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gA4",tId:"t1",group:"A",homeTeam:"México 🇲🇽",awayTeam:"Corea del Sur 🇰🇷",date:"2026-06-18",time:"23:00",stage:"Grupo A",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gA5",tId:"t1",group:"A",homeTeam:"TBD:Play-off UEFA D",awayTeam:"México 🇲🇽",date:"2026-06-24",time:"21:00",stage:"Grupo A",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gA6",tId:"t1",group:"A",homeTeam:"Sudáfrica 🇿🇦",awayTeam:"Corea del Sur 🇰🇷",date:"2026-06-24",time:"21:00",stage:"Grupo A",homeScore:null,awayScore:null,status:"upcoming"},
  // GRUPO B
  {id:"gB1",tId:"t1",group:"B",homeTeam:"Canadá 🇨🇦",awayTeam:"TBD:Play-off UEFA A",date:"2026-06-12",time:"21:00",stage:"Grupo B",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gB2",tId:"t1",group:"B",homeTeam:"Qatar 🇶🇦",awayTeam:"Suiza 🇨🇭",date:"2026-06-13",time:"21:00",stage:"Grupo B",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gB3",tId:"t1",group:"B",homeTeam:"Suiza 🇨🇭",awayTeam:"TBD:Play-off UEFA A",date:"2026-06-18",time:"21:00",stage:"Grupo B",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gB4",tId:"t1",group:"B",homeTeam:"Canadá 🇨🇦",awayTeam:"Qatar 🇶🇦",date:"2026-06-18",time:"18:00",stage:"Grupo B",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gB5",tId:"t1",group:"B",homeTeam:"Suiza 🇨🇭",awayTeam:"Canadá 🇨🇦",date:"2026-06-24",time:"21:00",stage:"Grupo B",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gB6",tId:"t1",group:"B",homeTeam:"TBD:Play-off UEFA A",awayTeam:"Qatar 🇶🇦",date:"2026-06-24",time:"21:00",stage:"Grupo B",homeScore:null,awayScore:null,status:"upcoming"},
  // GRUPO C
  {id:"gC1",tId:"t1",group:"C",homeTeam:"Brasil 🇧🇷",awayTeam:"Marruecos 🇲🇦",date:"2026-06-13",time:"00:00",stage:"Grupo C",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gC2",tId:"t1",group:"C",homeTeam:"Haití 🇭🇹",awayTeam:"Escocia 🏴󠁧󠁢󠁳󠁣󠁴󠁿",date:"2026-06-14",time:"03:00",stage:"Grupo C",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gC3",tId:"t1",group:"C",homeTeam:"Escocia 🏴󠁧󠁢󠁳󠁣󠁴󠁿",awayTeam:"Marruecos 🇲🇦",date:"2026-06-19",time:"00:00",stage:"Grupo C",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gC4",tId:"t1",group:"C",homeTeam:"Brasil 🇧🇷",awayTeam:"Haití 🇭🇹",date:"2026-06-20",time:"03:00",stage:"Grupo C",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gC5",tId:"t1",group:"C",homeTeam:"Escocia 🏴󠁧󠁢󠁳󠁣󠁴󠁿",awayTeam:"Brasil 🇧🇷",date:"2026-06-24",time:"00:00",stage:"Grupo C",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gC6",tId:"t1",group:"C",homeTeam:"Marruecos 🇲🇦",awayTeam:"Haití 🇭🇹",date:"2026-06-24",time:"00:00",stage:"Grupo C",homeScore:null,awayScore:null,status:"upcoming"},
  // GRUPO D
  {id:"gD1",tId:"t1",group:"D",homeTeam:"Estados Unidos 🇺🇸",awayTeam:"Paraguay 🇵🇾",date:"2026-06-12",time:"03:00",stage:"Grupo D",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gD2",tId:"t1",group:"D",homeTeam:"Australia 🇦🇺",awayTeam:"TBD:Play-off UEFA C",date:"2026-06-14",time:"03:00",stage:"Grupo D",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gD3",tId:"t1",group:"D",homeTeam:"Estados Unidos 🇺🇸",awayTeam:"Australia 🇦🇺",date:"2026-06-19",time:"21:00",stage:"Grupo D",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gD4",tId:"t1",group:"D",homeTeam:"TBD:Play-off UEFA C",awayTeam:"Paraguay 🇵🇾",date:"2026-06-20",time:"03:00",stage:"Grupo D",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gD5",tId:"t1",group:"D",homeTeam:"TBD:Play-off UEFA C",awayTeam:"Estados Unidos 🇺🇸",date:"2026-06-25",time:"02:00",stage:"Grupo D",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gD6",tId:"t1",group:"D",homeTeam:"Paraguay 🇵🇾",awayTeam:"Australia 🇦🇺",date:"2026-06-25",time:"02:00",stage:"Grupo D",homeScore:null,awayScore:null,status:"upcoming"},
  // GRUPO E
  {id:"gE1",tId:"t1",group:"E",homeTeam:"Alemania 🇩🇪",awayTeam:"Curazao 🇨🇼",date:"2026-06-14",time:"19:00",stage:"Grupo E",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gE2",tId:"t1",group:"E",homeTeam:"Costa de Marfil 🇨🇮",awayTeam:"Ecuador 🇪🇨",date:"2026-06-15",time:"01:00",stage:"Grupo E",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gE3",tId:"t1",group:"E",homeTeam:"Alemania 🇩🇪",awayTeam:"Costa de Marfil 🇨🇮",date:"2026-06-20",time:"20:00",stage:"Grupo E",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gE4",tId:"t1",group:"E",homeTeam:"Ecuador 🇪🇨",awayTeam:"Curazao 🇨🇼",date:"2026-06-21",time:"02:00",stage:"Grupo E",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gE5",tId:"t1",group:"E",homeTeam:"Ecuador 🇪🇨",awayTeam:"Alemania 🇩🇪",date:"2026-06-25",time:"20:00",stage:"Grupo E",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gE6",tId:"t1",group:"E",homeTeam:"Curazao 🇨🇼",awayTeam:"Costa de Marfil 🇨🇮",date:"2026-06-25",time:"20:00",stage:"Grupo E",homeScore:null,awayScore:null,status:"upcoming"},
  // GRUPO F
  {id:"gF1",tId:"t1",group:"F",homeTeam:"Países Bajos 🇳🇱",awayTeam:"Japón 🇯🇵",date:"2026-06-14",time:"22:00",stage:"Grupo F",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gF2",tId:"t1",group:"F",homeTeam:"TBD:Play-off UEFA B",awayTeam:"Túnez 🇹🇳",date:"2026-06-15",time:"04:00",stage:"Grupo F",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gF3",tId:"t1",group:"F",homeTeam:"Países Bajos 🇳🇱",awayTeam:"TBD:Play-off UEFA B",date:"2026-06-20",time:"19:00",stage:"Grupo F",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gF4",tId:"t1",group:"F",homeTeam:"Túnez 🇹🇳",awayTeam:"Japón 🇯🇵",date:"2026-06-21",time:"04:00",stage:"Grupo F",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gF5",tId:"t1",group:"F",homeTeam:"Japón 🇯🇵",awayTeam:"TBD:Play-off UEFA B",date:"2026-06-25",time:"19:00",stage:"Grupo F",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gF6",tId:"t1",group:"F",homeTeam:"Túnez 🇹🇳",awayTeam:"Países Bajos 🇳🇱",date:"2026-06-25",time:"19:00",stage:"Grupo F",homeScore:null,awayScore:null,status:"upcoming"},
  // GRUPO G
  {id:"gG1",tId:"t1",group:"G",homeTeam:"Bélgica 🇧🇪",awayTeam:"Egipto 🇪🇬",date:"2026-06-15",time:"22:00",stage:"Grupo G",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gG2",tId:"t1",group:"G",homeTeam:"Irán 🇮🇷",awayTeam:"Nueva Zelanda 🇳🇿",date:"2026-06-16",time:"04:00",stage:"Grupo G",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gG3",tId:"t1",group:"G",homeTeam:"Bélgica 🇧🇪",awayTeam:"Irán 🇮🇷",date:"2026-06-21",time:"21:00",stage:"Grupo G",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gG4",tId:"t1",group:"G",homeTeam:"Nueva Zelanda 🇳🇿",awayTeam:"Egipto 🇪🇬",date:"2026-06-22",time:"03:00",stage:"Grupo G",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gG5",tId:"t1",group:"G",homeTeam:"Egipto 🇪🇬",awayTeam:"Irán 🇮🇷",date:"2026-06-26",time:"23:00",stage:"Grupo G",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gG6",tId:"t1",group:"G",homeTeam:"Nueva Zelanda 🇳🇿",awayTeam:"Bélgica 🇧🇪",date:"2026-06-26",time:"23:00",stage:"Grupo G",homeScore:null,awayScore:null,status:"upcoming"},
  // GRUPO H
  {id:"gH1",tId:"t1",group:"H",homeTeam:"España 🇪🇸",awayTeam:"Cabo Verde 🇨🇻",date:"2026-06-15",time:"19:00",stage:"Grupo H",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gH2",tId:"t1",group:"H",homeTeam:"Arabia Saudita 🇸🇦",awayTeam:"Uruguay 🇺🇾",date:"2026-06-16",time:"00:00",stage:"Grupo H",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gH3",tId:"t1",group:"H",homeTeam:"España 🇪🇸",awayTeam:"Arabia Saudita 🇸🇦",date:"2026-06-21",time:"18:00",stage:"Grupo H",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gH4",tId:"t1",group:"H",homeTeam:"Uruguay 🇺🇾",awayTeam:"Cabo Verde 🇨🇻",date:"2026-06-22",time:"00:00",stage:"Grupo H",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gH5",tId:"t1",group:"H",homeTeam:"Cabo Verde 🇨🇻",awayTeam:"Arabia Saudita 🇸🇦",date:"2026-06-27",time:"02:00",stage:"Grupo H",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gH6",tId:"t1",group:"H",homeTeam:"Uruguay 🇺🇾",awayTeam:"España 🇪🇸",date:"2026-06-27",time:"02:00",stage:"Grupo H",homeScore:null,awayScore:null,status:"upcoming"},
  // GRUPO I
  {id:"gI1",tId:"t1",group:"I",homeTeam:"Francia 🇫🇷",awayTeam:"Senegal 🇸🇳",date:"2026-06-16",time:"21:00",stage:"Grupo I",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gI2",tId:"t1",group:"I",homeTeam:"TBD:Play-off Intercontinental 2",awayTeam:"Noruega 🇳🇴",date:"2026-06-17",time:"00:00",stage:"Grupo I",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gI3",tId:"t1",group:"I",homeTeam:"Francia 🇫🇷",awayTeam:"TBD:Play-off Intercontinental 2",date:"2026-06-22",time:"23:00",stage:"Grupo I",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gI4",tId:"t1",group:"I",homeTeam:"Noruega 🇳🇴",awayTeam:"Senegal 🇸🇳",date:"2026-06-23",time:"02:00",stage:"Grupo I",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gI5",tId:"t1",group:"I",homeTeam:"Noruega 🇳🇴",awayTeam:"Francia 🇫🇷",date:"2026-06-26",time:"19:00",stage:"Grupo I",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gI6",tId:"t1",group:"I",homeTeam:"Senegal 🇸🇳",awayTeam:"TBD:Play-off Intercontinental 2",date:"2026-06-27",time:"19:00",stage:"Grupo I",homeScore:null,awayScore:null,status:"upcoming"},
  // GRUPO J
  {id:"gJ1",tId:"t1",group:"J",homeTeam:"Argentina 🇦🇷",awayTeam:"Argelia 🇩🇿",date:"2026-06-17",time:"03:00",stage:"Grupo J",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gJ2",tId:"t1",group:"J",homeTeam:"Austria 🇦🇹",awayTeam:"Jordania 🇯🇴",date:"2026-06-17",time:"04:00",stage:"Grupo J",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gJ3",tId:"t1",group:"J",homeTeam:"Argentina 🇦🇷",awayTeam:"Austria 🇦🇹",date:"2026-06-22",time:"19:00",stage:"Grupo J",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gJ4",tId:"t1",group:"J",homeTeam:"Jordania 🇯🇴",awayTeam:"Argelia 🇩🇿",date:"2026-06-23",time:"03:00",stage:"Grupo J",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gJ5",tId:"t1",group:"J",homeTeam:"Argelia 🇩🇿",awayTeam:"Austria 🇦🇹",date:"2026-06-28",time:"02:00",stage:"Grupo J",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gJ6",tId:"t1",group:"J",homeTeam:"Jordania 🇯🇴",awayTeam:"Argentina 🇦🇷",date:"2026-06-28",time:"02:00",stage:"Grupo J",homeScore:null,awayScore:null,status:"upcoming"},
  // GRUPO K
  {id:"gK1",tId:"t1",group:"K",homeTeam:"Portugal 🇵🇹",awayTeam:"TBD:Play-off Intercontinental 1",date:"2026-06-17",time:"19:00",stage:"Grupo K",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gK2",tId:"t1",group:"K",homeTeam:"Uzbekistán 🇺🇿",awayTeam:"Colombia 🇨🇴",date:"2026-06-18",time:"04:00",stage:"Grupo K",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gK3",tId:"t1",group:"K",homeTeam:"Portugal 🇵🇹",awayTeam:"Uzbekistán 🇺🇿",date:"2026-06-23",time:"19:00",stage:"Grupo K",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gK4",tId:"t1",group:"K",homeTeam:"Colombia 🇨🇴",awayTeam:"TBD:Play-off Intercontinental 1",date:"2026-06-24",time:"04:00",stage:"Grupo K",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gK5",tId:"t1",group:"K",homeTeam:"Colombia 🇨🇴",awayTeam:"Portugal 🇵🇹",date:"2026-06-28",time:"01:30",stage:"Grupo K",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gK6",tId:"t1",group:"K",homeTeam:"TBD:Play-off Intercontinental 1",awayTeam:"Uzbekistán 🇺🇿",date:"2026-06-28",time:"01:30",stage:"Grupo K",homeScore:null,awayScore:null,status:"upcoming"},
  // GRUPO L
  {id:"gL1",tId:"t1",group:"L",homeTeam:"Inglaterra 🏴󠁧󠁢󠁥󠁮󠁧󠁿",awayTeam:"Croacia 🇭🇷",date:"2026-06-17",time:"22:00",stage:"Grupo L",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gL2",tId:"t1",group:"L",homeTeam:"Ghana 🇬🇭",awayTeam:"Panamá 🇵🇦",date:"2026-06-18",time:"01:00",stage:"Grupo L",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gL3",tId:"t1",group:"L",homeTeam:"Inglaterra 🏴󠁧󠁢󠁥󠁮󠁧󠁿",awayTeam:"Ghana 🇬🇭",date:"2026-06-23",time:"22:00",stage:"Grupo L",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gL4",tId:"t1",group:"L",homeTeam:"Panamá 🇵🇦",awayTeam:"Croacia 🇭🇷",date:"2026-06-24",time:"01:00",stage:"Grupo L",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gL5",tId:"t1",group:"L",homeTeam:"Panamá 🇵🇦",awayTeam:"Inglaterra 🏴󠁧󠁢󠁥󠁮󠁧󠁿",date:"2026-06-27",time:"23:00",stage:"Grupo L",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"gL6",tId:"t1",group:"L",homeTeam:"Croacia 🇭🇷",awayTeam:"Ghana 🇬🇭",date:"2026-06-27",time:"23:00",stage:"Grupo L",homeScore:null,awayScore:null,status:"upcoming"},
  // RONDA DE 32
  {id:"r32_1",tId:"t1",group:"R32",homeTeam:"TBD:2° Grupo A",awayTeam:"TBD:2° Grupo B",date:"2026-06-28",time:"21:00",stage:"Ronda de 32",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"r32_2",tId:"t1",group:"R32",homeTeam:"TBD:1° Grupo C",awayTeam:"TBD:2° Grupo F",date:"2026-06-29",time:"19:00",stage:"Ronda de 32",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"r32_3",tId:"t1",group:"R32",homeTeam:"TBD:1° Grupo E",awayTeam:"TBD:Mejor 3° A/B/C/D/F",date:"2026-06-29",time:"22:30",stage:"Ronda de 32",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"r32_4",tId:"t1",group:"R32",homeTeam:"TBD:1° Grupo F",awayTeam:"TBD:2° Grupo C",date:"2026-06-30",time:"03:00",stage:"Ronda de 32",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"r32_5",tId:"t1",group:"R32",homeTeam:"TBD:2° Grupo E",awayTeam:"TBD:2° Grupo I",date:"2026-06-30",time:"19:00",stage:"Ronda de 32",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"r32_6",tId:"t1",group:"R32",homeTeam:"TBD:1° Grupo I",awayTeam:"TBD:Mejor 3° C/D/F/G/H",date:"2026-07-01",time:"01:00",stage:"Ronda de 32",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"r32_7",tId:"t1",group:"R32",homeTeam:"TBD:1° Grupo A",awayTeam:"TBD:Mejor 3° C/E/F/H/I",date:"2026-07-01",time:"03:00",stage:"Ronda de 32",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"r32_8",tId:"t1",group:"R32",homeTeam:"TBD:1° Grupo L",awayTeam:"TBD:Mejor 3° E/H/I/J/K",date:"2026-07-01",time:"18:00",stage:"Ronda de 32",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"r32_9",tId:"t1",group:"R32",homeTeam:"TBD:1° Grupo G",awayTeam:"TBD:Mejor 3° A/E/H/I/J",date:"2026-07-02",time:"20:00",stage:"Ronda de 32",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"r32_10",tId:"t1",group:"R32",homeTeam:"TBD:1° Grupo D",awayTeam:"TBD:Mejor 3° B/E/F/I/J",date:"2026-07-02",time:"02:00",stage:"Ronda de 32",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"r32_11",tId:"t1",group:"R32",homeTeam:"TBD:1° Grupo H",awayTeam:"TBD:2° Grupo J",date:"2026-07-02",time:"21:00",stage:"Ronda de 32",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"r32_12",tId:"t1",group:"R32",homeTeam:"TBD:2° Grupo K",awayTeam:"TBD:2° Grupo L",date:"2026-07-03",time:"01:00",stage:"Ronda de 32",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"r32_13",tId:"t1",group:"R32",homeTeam:"TBD:1° Grupo B",awayTeam:"TBD:Mejor 3° E/F/G/I/J",date:"2026-07-03",time:"03:00",stage:"Ronda de 32",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"r32_14",tId:"t1",group:"R32",homeTeam:"TBD:2° Grupo D",awayTeam:"TBD:2° Grupo G",date:"2026-07-03",time:"20:00",stage:"Ronda de 32",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"r32_15",tId:"t1",group:"R32",homeTeam:"TBD:1° Grupo J",awayTeam:"TBD:2° Grupo H",date:"2026-07-04",time:"00:00",stage:"Ronda de 32",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"r32_16",tId:"t1",group:"R32",homeTeam:"TBD:1° Grupo K",awayTeam:"TBD:Mejor 3° D/E/I/J/L",date:"2026-07-04",time:"01:30",stage:"Ronda de 32",homeScore:null,awayScore:null,status:"upcoming"},
  // OCTAVOS DE FINAL
  {id:"r16_1",tId:"t1",group:"R16",homeTeam:"TBD:Gan. R32-1",awayTeam:"TBD:Gan. R32-2",date:"2026-07-04",time:"19:00",stage:"Octavos de final",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"r16_2",tId:"t1",group:"R16",homeTeam:"TBD:Gan. R32-3",awayTeam:"TBD:Gan. R32-4",date:"2026-07-05",time:"01:00",stage:"Octavos de final",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"r16_3",tId:"t1",group:"R16",homeTeam:"TBD:Gan. R32-5",awayTeam:"TBD:Gan. R32-6",date:"2026-07-05",time:"22:00",stage:"Octavos de final",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"r16_4",tId:"t1",group:"R16",homeTeam:"TBD:Gan. R32-7",awayTeam:"TBD:Gan. R32-8",date:"2026-07-06",time:"02:00",stage:"Octavos de final",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"r16_5",tId:"t1",group:"R16",homeTeam:"TBD:Gan. R32-9",awayTeam:"TBD:Gan. R32-10",date:"2026-07-06",time:"21:00",stage:"Octavos de final",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"r16_6",tId:"t1",group:"R16",homeTeam:"TBD:Gan. R32-11",awayTeam:"TBD:Gan. R32-12",date:"2026-07-07",time:"03:00",stage:"Octavos de final",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"r16_7",tId:"t1",group:"R16",homeTeam:"TBD:Gan. R32-13",awayTeam:"TBD:Gan. R32-14",date:"2026-07-07",time:"18:00",stage:"Octavos de final",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"r16_8",tId:"t1",group:"R16",homeTeam:"TBD:Gan. R32-15",awayTeam:"TBD:Gan. R32-16",date:"2026-07-08",time:"22:00",stage:"Octavos de final",homeScore:null,awayScore:null,status:"upcoming"},
  // CUARTOS DE FINAL
  {id:"qf1",tId:"t1",group:"QF",homeTeam:"TBD:Gan. Oct-1",awayTeam:"TBD:Gan. Oct-2",date:"2026-07-09",time:"22:00",stage:"Cuartos de final",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"qf2",tId:"t1",group:"QF",homeTeam:"TBD:Gan. Oct-3",awayTeam:"TBD:Gan. Oct-4",date:"2026-07-10",time:"21:00",stage:"Cuartos de final",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"qf3",tId:"t1",group:"QF",homeTeam:"TBD:Gan. Oct-5",awayTeam:"TBD:Gan. Oct-6",date:"2026-07-11",time:"23:00",stage:"Cuartos de final",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"qf4",tId:"t1",group:"QF",homeTeam:"TBD:Gan. Oct-7",awayTeam:"TBD:Gan. Oct-8",date:"2026-07-12",time:"03:00",stage:"Cuartos de final",homeScore:null,awayScore:null,status:"upcoming"},
  // SEMIFINALES
  {id:"sf1",tId:"t1",group:"SF",homeTeam:"TBD:Gan. CF-1",awayTeam:"TBD:Gan. CF-2",date:"2026-07-14",time:"21:00",stage:"Semifinal",homeScore:null,awayScore:null,status:"upcoming"},
  {id:"sf2",tId:"t1",group:"SF",homeTeam:"TBD:Gan. CF-3",awayTeam:"TBD:Gan. CF-4",date:"2026-07-15",time:"23:00",stage:"Semifinal",homeScore:null,awayScore:null,status:"upcoming"},
  // TERCER PUESTO
  {id:"tp1",tId:"t1",group:"3P",homeTeam:"TBD:Per. SF-1",awayTeam:"TBD:Per. SF-2",date:"2026-07-18",time:"23:00",stage:"Tercer puesto",homeScore:null,awayScore:null,status:"upcoming"},
  // FINAL
  {id:"fin",tId:"t1",group:"FIN",homeTeam:"TBD:Gan. SF-1",awayTeam:"TBD:Gan. SF-2",date:"2026-07-19",time:"21:00",stage:"Final",homeScore:null,awayScore:null,status:"upcoming"},
];

// ============================================================
// FIFA API
// ============================================================
const FIFA_API = {
  BASE:"https://givevoicetofootball.fifa.com/api/v1",
  COMPETITIONS:{"FIFA World Cup":17,"FIFA Women's World Cup":103,"FIFA U-20 World Cup":104,"FIFA U-17 World Cup":107,"FIFA U-20 Women's World Cup":108,"FIFA Club World Cup":292,"FIFA Confederations Cup":102},
  async searchSeasons(name){
    try{const r=await fetch(`${FIFA_API.BASE}/seasons/search?name=${encodeURIComponent(name)}&count=10`,{headers:{"Accept":"application/json"}});if(!r.ok)throw new Error(`HTTP ${r.status}`);return await r.json();}
    catch(e){return{error:e.message};}
  },
  async getMatches(idC,idS){
    try{const r=await fetch(`${FIFA_API.BASE}/calendar/matches?idSeason=${idS}&idCompetition=${idC}&count=100`,{headers:{"Accept":"application/json"}});if(!r.ok)throw new Error(`HTTP ${r.status}`);return await r.json();}
    catch(e){return{error:e.message};}
  },
  transformMatch(m,tId){
    return{id:"fifa_"+m.IdMatch,tId,group:m.GroupName?.[0]?.Description||"?",homeTeam:m.Home?.TeamName?.[0]?.Description||"TBD",awayTeam:m.Away?.TeamName?.[0]?.Description||"TBD",date:m.Date?.split("T")[0]||"",time:m.Date?.split("T")[1]?.slice(0,5)||"00:00",stage:m.StageName?.[0]?.Description||"Fase de grupos",homeScore:m.HomeTeamScore??null,awayScore:m.AwayTeamScore??null,status:m.MatchStatus===3?"finished":m.MatchStatus===1?"active":"upcoming"};
  }
};

// ============================================================
// STORE — universal adapter
// Uses window.storage (Claude artifact) when available,
// falls back to localStorage (local dev / Vercel deploy)
// ============================================================
const Store = {
  // Detect which backend to use
  _useWindowStorage() {
    try { return typeof window.storage !== "undefined" && typeof window.storage.get === "function"; }
    catch { return false; }
  },

  async get(key) {
    try {
      if (Store._useWindowStorage()) {
        const r = await window.storage.get(key);
        return r ? JSON.parse(r.value) : null;
      } else {
        const raw = localStorage.getItem("sc:" + key);
        return raw ? JSON.parse(raw) : null;
      }
    } catch { return null; }
  },

  async set(key, val) {
    try {
      if (Store._useWindowStorage()) {
        await window.storage.set(key, JSON.stringify(val));
      } else {
        localStorage.setItem("sc:" + key, JSON.stringify(val));
      }
      return true;
    } catch { return false; }
  },

  async init() {
    if(!(await Store.get("db:users")))           await Store.set("db:users", SEED_USERS);
    if(!(await Store.get("db:tournaments")))      await Store.set("db:tournaments", SEED_TOURNAMENTS);
    if(!(await Store.get("db:invitations")))      await Store.set("db:invitations", []);
    if(!(await Store.get("db:audit")))            await Store.set("db:audit", []);

    // ── DATA MIGRATION v2 ───────────────────────────────────────
    // If matches for t1 exist but are the old 16-match version,
    // replace them with the complete 104-match 2026 World Cup fixture.
    const existingMatches = await Store.get("db:matches:t1");
    const needsMigration  = !existingMatches || existingMatches.length < 72;
    if (needsMigration) {
      await Store.set("db:matches:t1", SEED_MATCHES_T1);
    }

    // Also update tournament record with new group list if outdated
    const tournaments = await Store.get("db:tournaments") || [];
    const t1 = tournaments.find(t => t.id === "t1");
    if (t1 && t1.groups && t1.groups.length < 12) {
      const idx = tournaments.indexOf(t1);
      tournaments[idx] = { ...SEED_TOURNAMENTS[0] };
      await Store.set("db:tournaments", tournaments);
    }

    if(!(await Store.get("db:predictions:t1")))   await Store.set("db:predictions:t1", []);
    if(!(await Store.get("db:leaderboard:t1")))   await Store.set("db:leaderboard:t1", {});
  }
};

// ============================================================
// API LAYER
// ============================================================
const API = {
  // AUTH
  async login(username, password) {
    if(!Security.rateLimit("rl:"+username,5,60000)) return {error:"Demasiados intentos. Esperá 60s."};
    const users=await Store.get("db:users")||[];
    const u=users.find(x=>x.username===Security.sanitize(username));
    if(!u) return {error:"Credenciales inválidas"};
    if(!u.active) return {error:"Tu cuenta está desactivada. Contactá al administrador."};
    // Demo mode: accept any password for seed users (passwordHash === "demo_hash")
    if(u.passwordHash !== "demo_hash") {
      const hash = await Security.hashPassword(password||"");
      if(hash !== u.passwordHash) return {error:"Credenciales inválidas"};
    }
    const token=Security.generateToken(u.id);
    await API._audit(u.id,"LOGIN",{username});
    return {token,user:{id:u.id,username:u.username,role:u.role,avatar:u.avatar}};
  },

  // USER MANAGEMENT (admin)
  async getUsers(adminId, token) {
    const p=Security.validateToken(token);
    if(!p) return {error:"Token inválido"};
    const users=await Store.get("db:users")||[];
    if(!users.find(u=>u.id===p.userId&&u.role==="admin")) return {error:"Acceso denegado (A01)"};
    // Never return passwords
    return {success:true, users: users.map(u=>({id:u.id,username:u.username,role:u.role,avatar:u.avatar,active:u.active,createdAt:u.createdAt}))};
  },

  async adminCreateUser(adminId, data, token) {
    const p=Security.validateToken(token);
    if(!p) return {error:"Token inválido"};
    const users=await Store.get("db:users")||[];
    if(!users.find(u=>u.id===p.userId&&u.role==="admin")) return {error:"Acceso denegado (A01)"};
    // Validations
    if(!Security.validateUsername(data.username)) return {error:"Usuario inválido. Solo letras, números y _ (3-20 chars)"};
    if(!Security.validatePassword(data.password||"")) return {error:"Contraseña requerida (mínimo 4 caracteres)"};
    if(users.find(u=>u.username.toLowerCase()===data.username.toLowerCase())) return {error:"Ese nombre de usuario ya existe"};
    const role=data.role==="admin"?"admin":"user";
    const avatar=AVATARS.includes(data.avatar)?data.avatar:"⚽";
    const passwordHash = await Security.hashPassword(data.password);
    const newUser = {
      id:"u_"+Date.now(),
      username:Security.sanitize(data.username),
      passwordHash,
      role,
      avatar,
      active:true,
      createdAt:new Date().toISOString().split("T")[0],
    };
    users.push(newUser);
    await Store.set("db:users",users);
    await API._audit(adminId,"CREATE_USER",{username:newUser.username,role});
    return {success:true, user:{id:newUser.id,username:newUser.username,role:newUser.role,avatar:newUser.avatar,active:newUser.active,createdAt:newUser.createdAt}};
  },

  async adminUpdateUser(adminId, userId, fields, token) {
    const p=Security.validateToken(token);
    if(!p) return {error:"Token inválido"};
    const users=await Store.get("db:users")||[];
    if(!users.find(u=>u.id===p.userId&&u.role==="admin")) return {error:"Acceso denegado (A01)"};
    const idx=users.findIndex(u=>u.id===userId);
    if(idx<0) return {error:"Usuario no encontrado"};
    if(users[idx].id==="u1"&&fields.role&&fields.role!=="admin") return {error:"No se puede cambiar el rol del admin principal"};
    // Update allowed fields
    if(fields.role!==undefined && ["admin","user"].includes(fields.role)) users[idx].role=fields.role;
    if(fields.active!==undefined) users[idx].active=Boolean(fields.active);
    if(fields.avatar!==undefined && AVATARS.includes(fields.avatar)) users[idx].avatar=fields.avatar;
    if(fields.password) {
      if(!Security.validatePassword(fields.password)) return {error:"Contraseña inválida (mínimo 4 caracteres)"};
      users[idx].passwordHash = await Security.hashPassword(fields.password);
    }
    await Store.set("db:users",users);
    await API._audit(adminId,"UPDATE_USER",{userId,fields:Object.keys(fields)});
    return {success:true, user:{id:users[idx].id,username:users[idx].username,role:users[idx].role,avatar:users[idx].avatar,active:users[idx].active}};
  },

  async adminDeleteUser(adminId, userId, token) {
    const p=Security.validateToken(token);
    if(!p) return {error:"Token inválido"};
    const users=await Store.get("db:users")||[];
    if(!users.find(u=>u.id===p.userId&&u.role==="admin")) return {error:"Acceso denegado (A01)"};
    if(userId==="u1") return {error:"No se puede eliminar el administrador principal"};
    if(userId===adminId) return {error:"No podés eliminarte a vos mismo"};
    const filtered=users.filter(u=>u.id!==userId);
    if(filtered.length===users.length) return {error:"Usuario no encontrado"};
    await Store.set("db:users",filtered);
    await API._audit(adminId,"DELETE_USER",{userId});
    return {success:true};
  },

  // ── INVITATION SYSTEM ──────────────────────────────────────
  // Schema: { id, code, tId, tName, invitedBy, invitedByName,
  //           status: "pending"|"registered"|"approved"|"rejected",
  //           newUsername, newPasswordHash, newAvatar,
  //           createdAt, resolvedAt }
  // Flow:
  //   1. Any active user → createInvitation(tId)  → gets a code
  //   2. Invitee opens app → sees "Tengo un código" → registerWithCode()
  //   3. Admin → approveInvitation() / rejectInvitation()
  //   4. On approve → user is created active, can login immediately

  async createInvitation(userId, tId) {
    const users  = await Store.get("db:users") || [];
    const inviter = users.find(u => u.id === userId && u.active);
    if (!inviter) return { error: "Usuario no encontrado" };
    const tournaments = await Store.get("db:tournaments") || [];
    const tournament  = tournaments.find(t => t.id === tId);
    if (!tournament) return { error: "Torneo no encontrado" };
    // Rate limit: max 5 active invitations per user
    const invitations = await Store.get("db:invitations") || [];
    const activeByUser = invitations.filter(i => i.invitedBy === userId && i.status === "pending");
    if (activeByUser.length >= 5) return { error: "Límite de 5 invitaciones pendientes por usuario" };
    // Generate unique 8-char alphanumeric code
    const code = Math.random().toString(36).slice(2,6).toUpperCase() +
                 Math.random().toString(36).slice(2,6).toUpperCase();
    const inv = {
      id: "inv_" + Date.now(),
      code,
      tId,
      tName: tournament.name,
      invitedBy: userId,
      invitedByName: inviter.username,
      status: "pending",
      newUsername: null, newPasswordHash: null, newAvatar: null,
      createdAt: new Date().toISOString(),
      resolvedAt: null,
    };
    invitations.push(inv);
    await Store.set("db:invitations", invitations);
    await API._audit(userId, "CREATE_INVITATION", { code, tId });
    return { success: true, invitation: inv };
  },

  async registerWithCode(code, username, password, avatar) {
    if (!Security.rateLimit("rl:reg:" + code, 5, 300000))
      return { error: "Demasiados intentos con este código. Esperá 5 minutos." };
    const invitations = await Store.get("db:invitations") || [];
    const idx = invitations.findIndex(i => i.code === code.toUpperCase().trim() && i.status === "pending");
    if (idx < 0) return { error: "Código inválido o ya utilizado" };
    if (!Security.validateUsername(username)) return { error: "Usuario inválido (3-20 chars, letras/números/_)" };
    if (!Security.validatePassword(password)) return { error: "Contraseña mínimo 4 caracteres" };
    const users = await Store.get("db:users") || [];
    if (users.find(u => u.username.toLowerCase() === username.toLowerCase()))
      return { error: "Ese nombre de usuario ya existe" };
    const validAvatars = AVATARS;
    const safeAvatar = validAvatars.includes(avatar) ? avatar : "⚽";
    const passwordHash = await Security.hashPassword(password);
    invitations[idx] = {
      ...invitations[idx],
      status: "registered",
      newUsername: Security.sanitize(username),
      newPasswordHash: passwordHash,
      newAvatar: safeAvatar,
    };
    await Store.set("db:invitations", invitations);
    await API._audit("anon", "REGISTER_WITH_CODE", { code, username });
    return { success: true, invitation: invitations[idx] };
  },

  async getInvitations(adminId, token) {
    const p = Security.validateToken(token);
    if (!p) return { error: "Token inválido" };
    const users = await Store.get("db:users") || [];
    if (!users.find(u => u.id === p.userId && u.role === "admin"))
      return { error: "Acceso denegado (A01)" };
    const invitations = await Store.get("db:invitations") || [];
    return { success: true, invitations };
  },

  async getMyInvitations(userId) {
    const invitations = await Store.get("db:invitations") || [];
    return invitations.filter(i => i.invitedBy === userId);
  },

  async approveInvitation(adminId, invId, token) {
    const p = Security.validateToken(token);
    if (!p) return { error: "Token inválido" };
    const users = await Store.get("db:users") || [];
    if (!users.find(u => u.id === p.userId && u.role === "admin"))
      return { error: "Acceso denegado (A01)" };
    const invitations = await Store.get("db:invitations") || [];
    const idx = invitations.findIndex(i => i.id === invId && i.status === "registered");
    if (idx < 0) return { error: "Invitación no encontrada o en estado incorrecto" };
    const inv = invitations[idx];
    // Check username not taken (could have been created in the meantime)
    if (users.find(u => u.username.toLowerCase() === inv.newUsername.toLowerCase()))
      return { error: "El nombre de usuario ya fue tomado por otro registro" };
    const newUser = {
      id: "u_" + Date.now(),
      username: inv.newUsername,
      passwordHash: inv.newPasswordHash,
      role: "user",
      avatar: inv.newAvatar,
      active: true,
      createdAt: new Date().toISOString().split("T")[0],
      invitedBy: inv.invitedBy,
      invitedByName: inv.invitedByName,
    };
    users.push(newUser);
    await Store.set("db:users", users);
    invitations[idx] = { ...inv, status: "approved", resolvedAt: new Date().toISOString() };
    await Store.set("db:invitations", invitations);
    await API._audit(adminId, "APPROVE_INVITATION", { invId, username: inv.newUsername });
    return { success: true, user: newUser };
  },

  async rejectInvitation(adminId, invId, token) {
    const p = Security.validateToken(token);
    if (!p) return { error: "Token inválido" };
    const users = await Store.get("db:users") || [];
    if (!users.find(u => u.id === p.userId && u.role === "admin"))
      return { error: "Acceso denegado (A01)" };
    const invitations = await Store.get("db:invitations") || [];
    const idx = invitations.findIndex(i => i.id === invId && ["pending","registered"].includes(i.status));
    if (idx < 0) return { error: "Invitación no encontrada" };
    invitations[idx] = { ...invitations[idx], status: "rejected", resolvedAt: new Date().toISOString() };
    await Store.set("db:invitations", invitations);
    await API._audit(adminId, "REJECT_INVITATION", { invId });
    return { success: true };
  },

  async cancelInvitation(userId, invId) {
    const invitations = await Store.get("db:invitations") || [];
    const idx = invitations.findIndex(i => i.id === invId && i.invitedBy === userId && i.status === "pending");
    if (idx < 0) return { error: "Invitación no encontrada" };
    invitations[idx] = { ...invitations[idx], status: "rejected", resolvedAt: new Date().toISOString() };
    await Store.set("db:invitations", invitations);
    await API._audit(userId, "CANCEL_INVITATION", { invId });
    return { success: true };
  },

  // TOURNAMENTS
  async getTournaments(){return (await Store.get("db:tournaments"))||[];},
  async getTournament(tId){const l=await Store.get("db:tournaments")||[];return l.find(t=>t.id===tId)||null;},

  async adminCreateTournament(adminId,data,token){
    const p=Security.validateToken(token);if(!p)return{error:"Token inválido"};
    const users=await Store.get("db:users")||[];if(!users.find(u=>u.id===p.userId&&u.role==="admin"))return{error:"Acceso denegado (A01)"};
    if(!data.name||!data.startDate||!data.endDate)return{error:"Nombre y fechas son requeridos"};
    const list=await Store.get("db:tournaments")||[];
    const tId="t_"+Date.now();
    const groups=(data.groups||"").split(",").map(g=>g.trim().toUpperCase()).filter(Boolean);
    const t={id:tId,name:Security.sanitize(data.name),shortName:Security.sanitize(data.shortName||data.name.split(" ").slice(-2).join(" ")),region:Security.sanitize(data.region||"Global"),status:["upcoming","active","finished"].includes(data.status)?data.status:"upcoming",logo:["🌍","🌎","🌏","⚽","🏆","⭐","🥇","🎯"].includes(data.logo)?data.logo:"🏆",startDate:Security.sanitize(data.startDate),endDate:Security.sanitize(data.endDate),groups:groups.length?groups:["A","B","C","D"],source:data.source||"manual",fifaCompId:data.fifaCompId||null,fifaSeasonId:data.fifaSeasonId||null};
    list.push(t);await Store.set("db:tournaments",list);await Store.set("db:matches:"+tId,[]);await Store.set("db:predictions:"+tId,[]);await Store.set("db:leaderboard:"+tId,{});
    await API._audit(adminId,"CREATE_TOURNAMENT",{tId,name:t.name});return{success:true,tournament:t};
  },
  async adminDeleteTournament(adminId,tId,token){
    const p=Security.validateToken(token);if(!p)return{error:"Token inválido"};
    const users=await Store.get("db:users")||[];if(!users.find(u=>u.id===p.userId&&u.role==="admin"))return{error:"Acceso denegado (A01)"};
    if(tId==="t1")return{error:"No se puede eliminar el torneo base"};
    const list=await Store.get("db:tournaments")||[];const f=list.filter(t=>t.id!==tId);if(f.length===list.length)return{error:"No encontrado"};
    await Store.set("db:tournaments",f);await API._audit(adminId,"DELETE_TOURNAMENT",{tId});return{success:true};
  },
  async adminUpdateTournament(adminId,tId,fields,token){
    const p=Security.validateToken(token);if(!p)return{error:"Token inválido"};
    const users=await Store.get("db:users")||[];if(!users.find(u=>u.id===p.userId&&u.role==="admin"))return{error:"Acceso denegado (A01)"};
    const list=await Store.get("db:tournaments")||[];const idx=list.findIndex(t=>t.id===tId);if(idx<0)return{error:"No encontrado"};
    const allowed=["status","name","startDate","endDate","region"];const safe={};
    for(const k of allowed)if(fields[k]!==undefined)safe[k]=Security.sanitize(String(fields[k]));
    list[idx]={...list[idx],...safe};await Store.set("db:tournaments",list);await API._audit(adminId,"UPDATE_TOURNAMENT",{tId,...safe});return{success:true,tournament:list[idx]};
  },

  // MATCHES
  async adminAddMatch(adminId,tId,matchData,token){
    const p=Security.validateToken(token);if(!p)return{error:"Token inválido"};
    const users=await Store.get("db:users")||[];if(!users.find(u=>u.id===p.userId&&u.role==="admin"))return{error:"Acceso denegado (A01)"};
    if(!matchData.homeTeam||!matchData.awayTeam)return{error:"Equipos requeridos"};
    const key="db:matches:"+tId;const matches=await Store.get(key)||[];
    const match={
      id:"m_"+Date.now(),
      tId,
      group:Security.sanitize(matchData.group||"A"),
      stage:Security.sanitize(matchData.stage||"Grupo "+matchData.group),
      homeTeam:Security.sanitize(matchData.homeTeam),
      awayTeam:Security.sanitize(matchData.awayTeam),
      date:Security.sanitize(matchData.date||""),
      time:Security.sanitize(matchData.time||"18:00"),
      homeScore:null,awayScore:null,status:"upcoming",
      // Dynamic propagation fields (optional)
      ...(matchData.nextMatchWinnerId  && {nextMatchWinnerId:  Security.sanitize(matchData.nextMatchWinnerId)}),
      ...(matchData.nextMatchWinnerSlot&& {nextMatchWinnerSlot:matchData.nextMatchWinnerSlot==="away"?"away":"home"}),
      ...(matchData.nextMatchLoserId   && {nextMatchLoserId:   Security.sanitize(matchData.nextMatchLoserId)}),
      ...(matchData.nextMatchLoserSlot && {nextMatchLoserSlot: matchData.nextMatchLoserSlot==="away"?"away":"home"}),
    };
    matches.push(match);await Store.set(key,matches);await API._audit(adminId,"ADD_MATCH",{tId,matchId:match.id});return{success:true,match};
  },
  async adminImportFromFIFA(adminId,tId,idC,idS,token){
    const p=Security.validateToken(token);if(!p)return{error:"Token inválido"};
    const users=await Store.get("db:users")||[];if(!users.find(u=>u.id===p.userId&&u.role==="admin"))return{error:"Acceso denegado (A01)"};
    const res=await FIFA_API.getMatches(idC,idS);if(res.error)return{error:"FIFA API: "+res.error,corsBlocked:true};
    const matches=(res.Results||[]).map(m=>FIFA_API.transformMatch(m,tId));if(!matches.length)return{error:"Sin partidos"};
    await Store.set("db:matches:"+tId,matches);await API._audit(adminId,"IMPORT_FIFA",{tId,count:matches.length});return{success:true,count:matches.length};
  },
  async getMatches(tId,userId){
    const matches=await Store.get("db:matches:"+tId)||[];const preds=await Store.get("db:predictions:"+tId)||[];
    return matches.map(m=>({...m,myPrediction:preds.find(p=>p.matchId===m.id&&p.userId===userId)||null}));
  },
  async adminUpdateMatch(adminId,tId,matchId,homeScore,awayScore,token){
    const p=Security.validateToken(token);if(!p)return{error:"Token inválido"};
    const users=await Store.get("db:users")||[];if(!users.find(u=>u.id===p.userId&&u.role==="admin"))return{error:"Acceso denegado (A01)"};
    if(!Security.validateScore(homeScore)||!Security.validateScore(awayScore))return{error:"Marcador inválido"};
    const key="db:matches:"+tId;const matches=await Store.get(key)||[];const idx=matches.findIndex(m=>m.id===matchId);if(idx<0)return{error:"No encontrado"};
    matches[idx]={...matches[idx],homeScore:parseInt(homeScore),awayScore:parseInt(awayScore),status:"finished"};
    await Store.set(key,matches);
    await API._calcPoints(tId,matchId,parseInt(homeScore),parseInt(awayScore));
    await API._propagateTBD(tId, matches[idx], parseInt(homeScore), parseInt(awayScore));
    await API._audit(adminId,"UPDATE_MATCH",{tId,matchId,homeScore,awayScore});return{success:true};
  },

  async savePrediction(userId,tId,matchId,homeScore,awayScore){
    if(!Security.validateScore(homeScore)||!Security.validateScore(awayScore))return{error:"Marcador inválido"};
    const matches=await Store.get("db:matches:"+tId)||[];const match=matches.find(m=>m.id===matchId);
    if(!match||match.status==="finished")return{error:"No se puede pronosticar"};
    const pKey="db:predictions:"+tId;const preds=await Store.get(pKey)||[];
    const idx=preds.findIndex(p=>p.matchId===matchId&&p.userId===userId);
    const pred={id:"p_"+Date.now(),userId,matchId,tId,homeScore:parseInt(homeScore),awayScore:parseInt(awayScore),createdAt:new Date().toISOString(),points:0};
    if(idx>=0)preds[idx]=pred;else preds.push(pred);
    await Store.set(pKey,preds);await API._audit(userId,"PREDICT",{tId,matchId,homeScore,awayScore});return{success:true,prediction:pred};
  },

  // ── TBD PROPAGATION — DINÁMICA (funciona para CUALQUIER torneo) ──
  //
  // Cada partido knockout puede tener en su schema:
  //   nextMatchWinnerId : id del partido al que avanza el ganador
  //   nextMatchWinnerSlot: "home" | "away"
  //   nextMatchLoserId  : id del partido al que va el perdedor (ej: 3er puesto)
  //   nextMatchLoserSlot: "home" | "away"
  //
  // Si estos campos existen → propagación dinámica (aplica a todos los torneos).
  // Si NO existen        → intenta el mapa estático legado del Mundial 2026.
  //
  async _propagateTBD(tId, match, homeScore, awayScore) {
    const key     = "db:matches:" + tId;
    const matches = await Store.get(key) || [];

    const winner = homeScore > awayScore ? match.homeTeam : match.awayTeam;
    const loser  = homeScore > awayScore ? match.awayTeam : match.homeTeam;

    // ── DYNAMIC PROPAGATION (nextMatchWinnerId / nextMatchLoserId) ──────────
    let changed = false;

    if (match.nextMatchWinnerId) {
      const idx = matches.findIndex(m => m.id === match.nextMatchWinnerId);
      if (idx >= 0) {
        const slot = match.nextMatchWinnerSlot === "away" ? "awayTeam" : "homeTeam";
        matches[idx][slot] = winner;
        changed = true;
      }
    }

    if (match.nextMatchLoserId) {
      const idx = matches.findIndex(m => m.id === match.nextMatchLoserId);
      if (idx >= 0) {
        const slot = match.nextMatchLoserSlot === "away" ? "awayTeam" : "homeTeam";
        matches[idx][slot] = loser;
        changed = true;
      }
    }

    if (changed) {
      await Store.set(key, matches);
      return;
    }

    // ── LEGACY STATIC MAP (Mundial 2026 hardcoded ids) ──────────────────────
    const isKnockout = ["Ronda de 32","Octavos de final","Cuartos de final","Semifinal"].includes(match.stage);
    if (!isKnockout) return;

    const WINNER_SLOTS = {
      "r32_1":"TBD:Gan. R32-1","r32_2":"TBD:Gan. R32-2","r32_3":"TBD:Gan. R32-3","r32_4":"TBD:Gan. R32-4",
      "r32_5":"TBD:Gan. R32-5","r32_6":"TBD:Gan. R32-6","r32_7":"TBD:Gan. R32-7","r32_8":"TBD:Gan. R32-8",
      "r32_9":"TBD:Gan. R32-9","r32_10":"TBD:Gan. R32-10","r32_11":"TBD:Gan. R32-11","r32_12":"TBD:Gan. R32-12",
      "r32_13":"TBD:Gan. R32-13","r32_14":"TBD:Gan. R32-14","r32_15":"TBD:Gan. R32-15","r32_16":"TBD:Gan. R32-16",
      "r16_1":"TBD:Gan. Oct-1","r16_2":"TBD:Gan. Oct-2","r16_3":"TBD:Gan. Oct-3","r16_4":"TBD:Gan. Oct-4",
      "r16_5":"TBD:Gan. Oct-5","r16_6":"TBD:Gan. Oct-6","r16_7":"TBD:Gan. Oct-7","r16_8":"TBD:Gan. Oct-8",
      "qf1":"TBD:Gan. CF-1","qf2":"TBD:Gan. CF-2","qf3":"TBD:Gan. CF-3","qf4":"TBD:Gan. CF-4",
      "sf1_winner":"TBD:Gan. SF-1","sf2_winner":"TBD:Gan. SF-2",
      "sf1_loser":"TBD:Per. SF-1","sf2_loser":"TBD:Per. SF-2",
    };

    let winSlot  = match.id === "sf1" ? WINNER_SLOTS["sf1_winner"]
                 : match.id === "sf2" ? WINNER_SLOTS["sf2_winner"]
                 : WINNER_SLOTS[match.id];
    let loseSlot = match.id === "sf1" ? WINNER_SLOTS["sf1_loser"]
                 : match.id === "sf2" ? WINNER_SLOTS["sf2_loser"]
                 : null;

    for (const m of matches) {
      if (winSlot  && (m.homeTeam === winSlot  || m.awayTeam === winSlot))  { m[m.homeTeam === winSlot  ? "homeTeam" : "awayTeam"] = winner; changed = true; }
      if (loseSlot && (m.homeTeam === loseSlot || m.awayTeam === loseSlot)) { m[m.homeTeam === loseSlot ? "homeTeam" : "awayTeam"] = loser;  changed = true; }
    }
    if (changed) await Store.set(key, matches);
  },

  async _calcPoints(tId,matchId,rH,rA){
    const pKey="db:predictions:"+tId;const lKey="db:leaderboard:"+tId;
    const preds=await Store.get(pKey)||[];const lb=await Store.get(lKey)||{};
    for(const p of preds){
      if(p.matchId!==matchId)continue;
      const exact=p.homeScore===rH&&p.awayScore===rA;
      const pW=p.homeScore>p.awayScore,rW=rH>rA,pD=p.homeScore===p.awayScore,rD=rH===rA,pAW=p.homeScore<p.awayScore,rAW=rH<rA;
      p.points=exact?3:((pW&&rW)||(pD&&rD)||(pAW&&rAW))?1:0;
      lb[p.userId]=(lb[p.userId]||0)+p.points;
    }
    await Store.set(pKey,preds);await Store.set(lKey,lb);
  },

  async getLeaderboard(tId){
    const users=await Store.get("db:users")||[];const preds=await Store.get("db:predictions:"+tId)||[];const lb=await Store.get("db:leaderboard:"+tId)||{};
    return users.filter(u=>u.role==="user"&&u.active).map(u=>({...u,points:lb[u.id]||0,predictions:preds.filter(p=>p.userId===u.id).length,exact:preds.filter(p=>p.userId===u.id&&p.points===3).length})).sort((a,b)=>b.points-a.points||b.predictions-a.predictions);
  },

  async getUserPoints(userId,tId){const lb=await Store.get("db:leaderboard:"+tId)||{};return lb[userId]||0;},

  async _audit(userId,action,details){
    const log=await Store.get("db:audit")||[];
    log.push({ts:new Date().toISOString(),userId,action,details});
    if(log.length>300)log.splice(0,log.length-300);
    await Store.set("db:audit",log);
  }
};

// ============================================================
// STYLES
// ============================================================
const S=`
@import url('https://fonts.googleapis.com/css2?family=Bebas+Neue&family=Barlow+Condensed:wght@400;600;700&family=Barlow:wght@300;400;500&display=swap');
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#080c14;--sf:#0d1520;--sf2:#111d2e;--bd:#1e3048;--gold:#c9a84c;--gold2:#e8c96a;--green:#00c878;--red:#ff4444;--blue:#4a9eff;--purple:#9b59b6;--tx:#e8edf5;--tx2:#8a9ab5;--tx3:#4a5f7a}
body{background:var(--bg);color:var(--tx);font-family:'Barlow',sans-serif}
.app{min-height:100vh;background:var(--bg);position:relative;overflow-x:hidden}
.app::before{content:'';position:fixed;inset:0;background:radial-gradient(ellipse 80% 50% at 20% 0%,rgba(201,168,76,.06) 0%,transparent 60%),radial-gradient(ellipse 60% 40% at 80% 100%,rgba(74,158,255,.05) 0%,transparent 60%);pointer-events:none;z-index:0}

.loader-wrap{min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:20px}
.loader-logo{font-size:72px;animation:spin 2s linear infinite}
@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}
.loader-txt{font-family:'Bebas Neue',sans-serif;font-size:18px;letter-spacing:6px;color:var(--gold)}

.login-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;position:relative;z-index:1}
.login-card{width:100%;max-width:420px;background:var(--sf);border:1px solid var(--bd);border-radius:2px;overflow:hidden}
.login-hdr{background:linear-gradient(135deg,#0d1520,#1a2a40);padding:44px 40px 32px;text-align:center;border-bottom:2px solid var(--gold)}
.login-logo{font-size:60px;display:block;margin-bottom:10px;filter:drop-shadow(0 0 20px rgba(201,168,76,.4))}
.login-title{font-family:'Bebas Neue',sans-serif;font-size:34px;letter-spacing:4px;color:var(--gold);line-height:1}
.login-sub{font-family:'Barlow Condensed',sans-serif;font-size:12px;letter-spacing:3px;color:var(--tx2);text-transform:uppercase;margin-top:5px}
.login-body{padding:32px 40px 36px}
.field{margin-bottom:16px}
.field label{display:block;font-size:10px;letter-spacing:2px;text-transform:uppercase;color:var(--tx2);margin-bottom:6px;font-family:'Barlow Condensed',sans-serif;font-weight:600}
.field input,.field select,.field textarea{width:100%;background:var(--bg);border:1px solid var(--bd);border-radius:2px;padding:10px 14px;color:var(--tx);font-family:'Barlow',sans-serif;font-size:14px;outline:none;transition:border-color .2s}
.field input:focus,.field select:focus,.field textarea:focus{border-color:var(--gold)}
.field select option{background:var(--bg)}
.btn{padding:9px 16px;border-radius:2px;border:none;cursor:pointer;font-family:'Bebas Neue',sans-serif;font-size:13px;letter-spacing:2px;transition:all .2s;white-space:nowrap;display:inline-flex;align-items:center;gap:6px}
.btn-gold{background:var(--gold);color:#080c14}.btn-gold:hover{background:var(--gold2)}
.btn-red{background:rgba(255,68,68,.15);border:1px solid rgba(255,68,68,.3);color:#ff8888}.btn-red:hover{background:rgba(255,68,68,.25)}
.btn-blue{background:rgba(74,158,255,.15);border:1px solid rgba(74,158,255,.3);color:var(--blue)}.btn-blue:hover{background:rgba(74,158,255,.25)}
.btn-green{background:rgba(0,200,120,.15);border:1px solid rgba(0,200,120,.3);color:var(--green)}.btn-green:hover{background:rgba(0,200,120,.25)}
.btn-ghost{background:transparent;border:1px solid var(--bd);color:var(--tx2)}.btn-ghost:hover{border-color:var(--gold);color:var(--gold)}
.btn:disabled{opacity:.45;cursor:not-allowed}
.btn-full{width:100%;font-size:17px;padding:13px;justify-content:center}
.demo-box{margin-top:20px;padding:14px;background:rgba(201,168,76,.05);border:1px solid rgba(201,168,76,.15);border-radius:2px}
.demo-box p{font-size:10px;letter-spacing:1.5px;text-transform:uppercase;color:var(--tx3);margin-bottom:8px;font-family:'Barlow Condensed',sans-serif}
.demo-btn{background:transparent;border:1px solid var(--bd);color:var(--tx2);padding:5px 11px;font-size:11px;border-radius:2px;cursor:pointer;margin:2px;font-family:'Barlow',sans-serif;transition:all .2s}
.demo-btn:hover{border-color:var(--gold);color:var(--gold)}
.msg-err{background:rgba(255,68,68,.1);border:1px solid rgba(255,68,68,.3);color:#ff8888;padding:9px 13px;border-radius:2px;font-size:12px;margin-bottom:12px}
.msg-ok{background:rgba(0,200,120,.1);border:1px solid rgba(0,200,120,.3);color:var(--green);padding:9px 13px;border-radius:2px;font-size:12px;margin-bottom:12px}
.msg-warn{background:rgba(201,168,76,.1);border:1px solid rgba(201,168,76,.3);color:var(--gold);padding:9px 13px;border-radius:2px;font-size:12px;margin-bottom:12px}

.navbar{position:sticky;top:0;z-index:100;background:rgba(8,12,20,.96);backdrop-filter:blur(14px);border-bottom:1px solid var(--bd);padding:0 22px;display:flex;align-items:center;justify-content:space-between;height:56px;gap:10px}
.nav-brand{font-family:'Bebas Neue',sans-serif;font-size:18px;letter-spacing:3px;color:var(--gold);white-space:nowrap;flex-shrink:0;display:flex;align-items:center;gap:8px}
.nav-tabs{display:flex;gap:0;flex:1;justify-content:center}
.nav-tab{background:transparent;border:none;color:var(--tx2);padding:6px 13px;font-family:'Barlow Condensed',sans-serif;font-size:11px;letter-spacing:2px;text-transform:uppercase;cursor:pointer;border-bottom:2px solid transparent;transition:all .2s;white-space:nowrap;height:56px;display:flex;align-items:center}
.nav-tab:hover{color:var(--tx)}
.nav-tab.active{color:var(--gold);border-bottom-color:var(--gold)}
.nav-right{display:flex;align-items:center;gap:8px;flex-shrink:0}
.user-badge{display:flex;align-items:center;gap:7px;background:var(--sf2);border:1px solid var(--bd);border-radius:20px;padding:3px 10px 3px 7px;font-size:12px}
.pts-chip{background:linear-gradient(135deg,var(--gold),var(--gold2));color:#080c14;padding:2px 7px;border-radius:10px;font-size:10px;font-weight:700;font-family:'Barlow Condensed',sans-serif;letter-spacing:1px}
.admin-chip{background:rgba(255,68,68,.15);color:#ff8888;border:1px solid rgba(255,68,68,.3);padding:2px 7px;border-radius:10px;font-size:9px;letter-spacing:2px;font-family:'Barlow Condensed',sans-serif;font-weight:700;text-transform:uppercase}

.content{position:relative;z-index:1;max-width:1120px;margin:0 auto;padding:26px 20px}
.sec-title{font-family:'Bebas Neue',sans-serif;font-size:26px;letter-spacing:4px;color:var(--tx);margin-bottom:5px}
.sec-sub{color:var(--tx3);font-size:11px;letter-spacing:1px;margin-bottom:22px;font-family:'Barlow Condensed',sans-serif;text-transform:uppercase}

/* USERS TABLE */
.users-table{background:var(--sf);border:1px solid var(--bd);border-radius:2px;overflow:hidden}
.ut-hdr{display:grid;grid-template-columns:44px 1fr 90px 90px 100px 120px;align-items:center;padding:10px 18px;background:var(--sf2);border-bottom:1px solid var(--bd);font-size:9px;letter-spacing:2px;text-transform:uppercase;color:var(--tx3);font-family:'Barlow Condensed',sans-serif;font-weight:600;gap:8px}
.ut-row{display:grid;grid-template-columns:44px 1fr 90px 90px 100px 120px;align-items:center;padding:12px 18px;border-bottom:1px solid var(--bd);transition:background .15s;gap:8px}
.ut-row:last-child{border-bottom:none}
.ut-row:hover{background:var(--sf2)}
.ut-avatar{font-size:22px;width:36px;height:36px;display:flex;align-items:center;justify-content:center;background:var(--sf2);border-radius:50%;border:1px solid var(--bd)}
.ut-name{font-weight:500;font-size:14px}
.ut-date{font-size:11px;color:var(--tx3);font-family:'Barlow Condensed',sans-serif}
.role-badge{font-size:9px;letter-spacing:1.5px;text-transform:uppercase;font-family:'Barlow Condensed',sans-serif;padding:2px 8px;border-radius:8px;font-weight:600;width:fit-content}
.rb-admin{background:rgba(255,68,68,.15);color:#ff8888;border:1px solid rgba(255,68,68,.28)}
.rb-user{background:rgba(74,158,255,.12);color:var(--blue);border:1px solid rgba(74,158,255,.25)}
.active-badge{font-size:9px;letter-spacing:1px;text-transform:uppercase;font-family:'Barlow Condensed',sans-serif;padding:2px 8px;border-radius:8px;font-weight:600;width:fit-content}
.ab-on{background:rgba(0,200,120,.12);color:var(--green);border:1px solid rgba(0,200,120,.25)}
.ab-off{background:rgba(100,100,100,.12);color:var(--tx3);border:1px solid rgba(100,100,100,.2)}
.ut-actions{display:flex;gap:6px;flex-wrap:wrap}
.icon-btn{background:transparent;border:1px solid var(--bd);color:var(--tx2);width:28px;height:28px;border-radius:2px;cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:13px;transition:all .2s;flex-shrink:0}
.icon-btn:hover{border-color:var(--gold);color:var(--gold)}
.icon-btn.danger:hover{border-color:var(--red);color:#ff8888}
.icon-btn.success:hover{border-color:var(--green);color:var(--green)}

/* MODAL */
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.75);backdrop-filter:blur(4px);z-index:200;display:flex;align-items:center;justify-content:center;padding:16px}
.modal{background:var(--sf);border:1px solid var(--bd);border-radius:2px;width:100%;max-width:500px;max-height:92vh;overflow-y:auto}
.modal-lg{max-width:660px}
.modal-hdr{padding:18px 22px;border-bottom:1px solid var(--bd);display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;background:var(--sf);z-index:1}
.modal-title{font-family:'Bebas Neue',sans-serif;font-size:20px;letter-spacing:3px;color:var(--tx)}
.modal-body{padding:22px}
.modal-footer{padding:14px 22px;border-top:1px solid var(--bd);display:flex;justify-content:flex-end;gap:10px;position:sticky;bottom:0;background:var(--sf)}
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.form-grid .field{margin-bottom:0}
.form-grid .full{grid-column:span 2}

/* AVATAR PICKER */
.avatar-picker{display:flex;flex-wrap:wrap;gap:6px;margin-top:6px}
.av-btn{font-size:22px;width:38px;height:38px;display:flex;align-items:center;justify-content:center;background:var(--bg);border:1px solid var(--bd);border-radius:4px;cursor:pointer;transition:all .15s}
.av-btn:hover,.av-btn.sel{border-color:var(--gold);background:rgba(201,168,76,.1)}

/* LOBBY */
.t-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:13px}
.t-card{background:var(--sf);border:1px solid var(--bd);border-radius:2px;overflow:hidden;cursor:pointer;transition:transform .15s,border-color .2s,box-shadow .2s}
.t-card:hover{transform:translateY(-2px);border-color:var(--gold);box-shadow:0 6px 24px rgba(201,168,76,.1)}
.t-card-top{padding:18px;display:flex;gap:13px;align-items:center;border-bottom:1px solid var(--bd)}
.t-card-logo{font-size:36px;width:56px;height:56px;display:flex;align-items:center;justify-content:center;background:var(--sf2);border-radius:2px;flex-shrink:0}
.t-card-name{font-family:'Bebas Neue',sans-serif;font-size:17px;letter-spacing:2px;line-height:1.2}
.t-card-meta{font-size:10px;color:var(--tx3);font-family:'Barlow Condensed',sans-serif;letter-spacing:1px;margin-top:3px}
.t-card-bot{padding:11px 18px;display:flex;align-items:center;justify-content:space-between}
.source-chip{font-size:9px;letter-spacing:1.5px;text-transform:uppercase;font-family:'Barlow Condensed',sans-serif;padding:2px 8px;border-radius:8px;font-weight:600}
.src-manual{background:rgba(74,158,255,.12);color:var(--blue);border:1px solid rgba(74,158,255,.25)}
.src-fifa{background:rgba(201,168,76,.12);color:var(--gold);border:1px solid rgba(201,168,76,.25)}
.status-badge{font-size:9px;letter-spacing:2px;text-transform:uppercase;font-family:'Barlow Condensed',sans-serif;padding:2px 9px;border-radius:8px;font-weight:600}
.s-up{background:rgba(201,168,76,.15);color:var(--gold);border:1px solid rgba(201,168,76,.3)}
.s-act{background:rgba(0,200,120,.15);color:var(--green);border:1px solid rgba(0,200,120,.3)}
.s-fin{background:rgba(100,100,100,.12);color:var(--tx3);border:1px solid rgba(100,100,100,.25)}

/* CREATE TOURNAMENT MODAL EXTRAS */
.tab-switcher{display:flex;gap:0;margin-bottom:18px;border:1px solid var(--bd);border-radius:2px;overflow:hidden}
.tab-sw-btn{flex:1;background:transparent;border:none;color:var(--tx2);padding:8px;font-family:'Barlow Condensed',sans-serif;font-size:11px;letter-spacing:2px;text-transform:uppercase;cursor:pointer;transition:all .2s;border-right:1px solid var(--bd)}
.tab-sw-btn:last-child{border-right:none}
.tab-sw-btn.active{background:var(--gold);color:#080c14;font-weight:700}
.fifa-sec{background:var(--sf2);border:1px solid var(--bd);border-radius:2px;padding:16px;margin-bottom:14px}
.fifa-sec-title{font-family:'Barlow Condensed',sans-serif;font-size:11px;letter-spacing:2px;text-transform:uppercase;color:var(--gold);margin-bottom:10px}
.comp-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:7px;margin-bottom:12px}
.comp-btn{background:var(--bg);border:1px solid var(--bd);color:var(--tx2);padding:7px 10px;border-radius:2px;cursor:pointer;font-family:'Barlow Condensed',sans-serif;font-size:10px;letter-spacing:1px;transition:all .2s;text-align:left}
.comp-btn:hover,.comp-btn.sel{border-color:var(--gold);color:var(--gold);background:rgba(201,168,76,.08)}
.search-results{max-height:180px;overflow-y:auto;border:1px solid var(--bd);border-radius:2px;margin-top:8px}
.sri{padding:9px 13px;border-bottom:1px solid var(--bd);cursor:pointer;transition:background .15s;display:flex;align-items:center;justify-content:space-between}
.sri:last-child{border-bottom:none}
.sri:hover{background:var(--sf2)}
.cors-box{background:rgba(255,68,68,.07);border:1px solid rgba(255,68,68,.2);border-radius:2px;padding:13px;margin-top:12px}
.cors-title{font-family:'Barlow Condensed',sans-serif;font-size:11px;letter-spacing:2px;text-transform:uppercase;color:#ff8888;margin-bottom:7px}
.cors-code{font-size:10px;color:var(--tx2);line-height:1.9;font-family:monospace}
.cors-code code{background:rgba(255,255,255,.06);padding:1px 5px;border-radius:2px;color:var(--blue)}

/* TOURNAMENT HERO */
.t-hero{background:var(--sf);border:1px solid var(--bd);border-radius:2px;overflow:hidden;margin-bottom:18px}
.t-hero-banner{background:linear-gradient(135deg,#0a1628,#162236,#0d1e35);padding:28px 32px;display:flex;align-items:center;gap:22px;border-bottom:2px solid var(--gold)}
.t-hero-logo{font-size:60px;filter:drop-shadow(0 0 18px rgba(201,168,76,.4))}
.t-hero-name{font-family:'Bebas Neue',sans-serif;font-size:28px;letter-spacing:4px;line-height:1}
.t-hero-region{font-family:'Barlow Condensed',sans-serif;font-size:11px;letter-spacing:3px;color:var(--gold);text-transform:uppercase;margin-top:4px}
.t-hero-dates{font-size:11px;color:var(--tx2);margin-top:5px}
.t-hero-footer{padding:10px 32px;display:flex;align-items:center;gap:13px;flex-wrap:wrap}

/* ADMIN PANEL */
.admin-panel{background:var(--sf);border:1px solid rgba(255,68,68,.2);border-radius:2px;overflow:hidden;margin-top:18px}
.ap-hdr{background:rgba(255,68,68,.04);border-bottom:1px solid rgba(255,68,68,.15);padding:9px 16px;display:flex;align-items:center;gap:8px}
.ap-title{font-family:'Barlow Condensed',sans-serif;font-size:10px;letter-spacing:2px;text-transform:uppercase;color:#ff8888;display:flex;align-items:center;gap:6px}
.ap-body{padding:14px 16px}
.ap-tabs{display:flex;gap:5px;margin-bottom:14px;flex-wrap:wrap}
.ap-tab{background:transparent;border:1px solid var(--bd);color:var(--tx3);padding:4px 11px;border-radius:2px;cursor:pointer;font-family:'Barlow Condensed',sans-serif;font-size:10px;letter-spacing:1.5px;text-transform:uppercase;transition:all .2s}
.ap-tab.active{border-color:#ff8888;color:#ff8888;background:rgba(255,68,68,.08)}
.ap-form{display:flex;gap:9px;flex-wrap:wrap;align-items:flex-end}
.ap-label{font-size:9px;letter-spacing:1.5px;text-transform:uppercase;color:var(--tx3);font-family:'Barlow Condensed',sans-serif;display:block;margin-bottom:4px}
.ap-input,.ap-select{background:var(--bg);border:1px solid var(--bd);border-radius:2px;color:var(--tx);padding:6px 10px;font-family:'Barlow',sans-serif;font-size:12px;outline:none;transition:border-color .2s}
.ap-input:focus,.ap-select:focus{border-color:#ff8888}
.mfg{display:grid;grid-template-columns:1fr 1fr;gap:9px;margin-bottom:10px}
.mfg .afield{grid-column:span 1}.mfg .afield.full{grid-column:span 2}
.afield{display:flex;flex-direction:column}

/* GROUPS */
.groups-nav{display:flex;gap:5px;flex-wrap:wrap;margin-bottom:16px}
.group-btn{background:var(--sf);border:1px solid var(--bd);color:var(--tx2);padding:5px 12px;border-radius:2px;cursor:pointer;font-family:'Barlow Condensed',sans-serif;font-size:11px;letter-spacing:2px;transition:all .2s}
.group-btn:hover,.group-btn.active{background:var(--gold);color:#080c14;border-color:var(--gold);font-weight:700}

/* MATCHES */
.matches-list{display:flex;flex-direction:column;gap:8px}
.match-card{background:var(--sf);border:1px solid var(--bd);border-radius:2px;overflow:hidden;transition:border-color .2s}
.match-card:hover{border-color:rgba(201,168,76,.3)}
.match-hdr{padding:6px 16px;background:var(--sf2);border-bottom:1px solid var(--bd);display:flex;align-items:center;justify-content:space-between;font-size:10px;letter-spacing:1.5px;text-transform:uppercase;color:var(--tx3);font-family:'Barlow Condensed',sans-serif}

/* Desktop: Local — Marcador — Visitante en una sola fila */
.match-body{padding:14px 16px;display:grid;grid-template-columns:1fr auto 1fr;align-items:center;gap:12px}
.team{font-family:'Barlow Condensed',sans-serif;font-size:13px;font-weight:600;letter-spacing:1px;line-height:1.3}
.team.home{text-align:right}
.team.away{text-align:left}
.match-center{display:contents}

/* Mobile: reorganiza en dos filas
   Fila 1: [Local vs Visitante] — los nombres separados a los extremos
   Fila 2: [input] — [input] centrados                                */
@media(max-width:600px){
  .match-body{
    display:flex;
    flex-wrap:wrap;
    align-items:center;
    gap:6px 4px;
    padding:12px 14px;
  }
  /* Nombres ocupan la primera fila completa */
  .team.home{order:1;flex:1;text-align:left}
  .team.away{order:2;flex:1;text-align:right}
  /* Centro (inputs/score) ocupa la segunda fila completa */
  .match-center{display:block;order:3;width:100%;flex-basis:100%}
}

.score-fin{display:flex;align-items:center;gap:7px;font-family:'Bebas Neue',sans-serif;font-size:24px;color:var(--gold);justify-content:center;min-width:64px}
.score-sep{color:var(--tx3);font-size:17px}
.score-row{display:flex;align-items:center;gap:6px;justify-content:center}
.sinput{width:46px;height:46px;background:var(--bg);border:2px solid var(--bd);border-radius:2px;color:var(--tx);font-family:'Bebas Neue',sans-serif;font-size:20px;text-align:center;outline:none;transition:border-color .2s}
.sinput:focus{border-color:var(--gold)}
.pred-btn{background:var(--gold);color:#080c14;border:none;border-radius:2px;padding:6px 12px;font-family:'Bebas Neue',sans-serif;font-size:11px;letter-spacing:2px;cursor:pointer;transition:background .2s}
.pred-btn:hover{background:var(--gold2)}.pred-btn.saved{background:var(--green);color:#fff}
.pred-btn:disabled{opacity:.45;cursor:wait}
.save-row{display:flex;justify-content:center;padding:8px 16px 12px;border-top:1px solid rgba(255,255,255,.04)}
.pred-badge{display:inline-flex;align-items:center;gap:5px;background:rgba(0,200,120,.09);border:1px solid rgba(0,200,120,.2);border-radius:2px;padding:3px 8px;font-size:10px;color:var(--green);font-family:'Barlow Condensed',sans-serif;letter-spacing:1px}
.pts-badge{background:rgba(201,168,76,.12);border:1px solid rgba(201,168,76,.28);border-radius:2px;padding:3px 7px;font-size:10px;color:var(--gold);font-family:'Barlow Condensed',sans-serif;letter-spacing:1px;margin-left:4px}
.admin-footer{padding:8px 16px;background:rgba(255,68,68,.03);border-top:1px solid var(--bd);display:flex;align-items:center;justify-content:center;gap:8px;flex-wrap:wrap}
.ainput{width:38px;height:30px;background:var(--bg);border:1px solid var(--bd);border-radius:2px;color:var(--tx);font-family:'Bebas Neue',sans-serif;font-size:15px;text-align:center;outline:none;transition:border-color .2s}
.ainput:focus{border-color:#ff8888}
.ares-btn{background:rgba(255,68,68,.12);border:1px solid rgba(255,68,68,.28);color:#ff8888;padding:5px 10px;border-radius:2px;font-family:'Barlow Condensed',sans-serif;font-size:10px;letter-spacing:1.5px;text-transform:uppercase;cursor:pointer;transition:all .2s}
.ares-btn:hover{background:rgba(255,68,68,.22)}.ares-btn:disabled{opacity:.45;cursor:wait}

/* LEADERBOARD */
.lb{background:var(--sf);border:1px solid var(--bd);border-radius:2px;overflow:hidden}
.lb-row{display:grid;grid-template-columns:48px 1fr 80px 64px 64px;align-items:center;padding:12px 20px;border-bottom:1px solid var(--bd);transition:background .15s}
.lb-row:last-child{border-bottom:none}
.lb-row:hover{background:var(--sf2)}
.lb-row.hdr{background:var(--sf2);font-size:9px;letter-spacing:2px;text-transform:uppercase;color:var(--tx3);font-family:'Barlow Condensed',sans-serif;font-weight:600}
.rank{font-family:'Bebas Neue',sans-serif;font-size:18px;color:var(--tx3)}
.rank.g{color:var(--gold)}.rank.s{color:#bbb}.rank.b{color:#cd7f32}
.lb-user{display:flex;align-items:center;gap:9px}
.lb-av{width:30px;height:30px;display:flex;align-items:center;justify-content:center;font-size:16px;background:var(--sf2);border-radius:50%;border:1px solid var(--bd)}
.lb-pts{font-family:'Bebas Neue',sans-serif;font-size:20px;color:var(--gold);text-align:right}
.lb-n{color:var(--tx3);font-size:11px;text-align:center}


.toast{position:fixed;bottom:20px;right:20px;background:var(--sf);border:1px solid var(--green);color:var(--green);padding:10px 15px;border-radius:2px;font-size:12px;z-index:999;animation:sIn .3s ease;font-family:'Barlow Condensed',sans-serif;letter-spacing:1px;max-width:280px}
.toast.err{border-color:var(--red);color:#ff8888}
@keyframes sIn{from{transform:translateX(110px);opacity:0}to{transform:translateX(0);opacity:1}}
.team.tbd{color:var(--tx3);font-style:italic;font-size:11px}
.tbd-match-note{text-align:center;font-size:10px;color:var(--tx3);font-family:'Barlow Condensed',sans-serif;letter-spacing:1px;padding:4px 0}
.stage-sep{background:var(--sf2);border-top:2px solid var(--gold);padding:6px 18px;font-family:'Bebas Neue',sans-serif;font-size:14px;letter-spacing:3px;color:var(--gold);margin-top:8px}
details summary::-webkit-details-marker{display:none}
details[open] summary{margin-bottom:0}
.db-dot{width:5px;height:5px;border-radius:50%;background:var(--green);display:inline-block;margin-right:5px;box-shadow:0 0 5px var(--green);vertical-align:middle}
.empty{text-align:center;padding:40px;color:var(--tx3);font-family:'Barlow Condensed',sans-serif;letter-spacing:2px;text-transform:uppercase;font-size:11px}
.pts-info{margin-top:11px;padding:10px 13px;background:var(--sf);border:1px solid var(--bd);border-radius:2px;font-size:11px;color:var(--tx3)}
.divider{border:none;border-top:1px solid var(--bd);margin:16px 0}
.confirm-modal{text-align:center;padding:8px 0}
.confirm-modal h3{font-family:'Bebas Neue',sans-serif;font-size:22px;letter-spacing:2px;margin-bottom:10px}
.confirm-modal p{color:var(--tx2);font-size:13px;line-height:1.6}

/* INVITATIONS */
.inv-code-box{background:var(--bg);border:2px dashed var(--gold);border-radius:4px;padding:20px;text-align:center;margin:16px 0}
.inv-code{font-family:'Bebas Neue',sans-serif;font-size:40px;letter-spacing:8px;color:var(--gold);display:block;margin-bottom:6px}
.inv-code-hint{font-size:11px;color:var(--tx3);font-family:'Barlow Condensed',sans-serif;letter-spacing:1px}
.inv-table{background:var(--sf);border:1px solid var(--bd);border-radius:2px;overflow:hidden}
.inv-row{display:grid;grid-template-columns:1fr 110px 120px 90px 120px;align-items:center;padding:11px 18px;border-bottom:1px solid var(--bd);gap:10px;transition:background .15s}
.inv-row:last-child{border-bottom:none}
.inv-row:hover{background:var(--sf2)}
.inv-row.hdr{background:var(--sf2);font-size:9px;letter-spacing:2px;text-transform:uppercase;color:var(--tx3);font-family:'Barlow Condensed',sans-serif;font-weight:600}
.inv-badge{font-size:9px;letter-spacing:1.5px;text-transform:uppercase;font-family:'Barlow Condensed',sans-serif;padding:2px 8px;border-radius:8px;font-weight:600;width:fit-content}
.ib-pending{background:rgba(201,168,76,.15);color:var(--gold);border:1px solid rgba(201,168,76,.3)}
.ib-registered{background:rgba(74,158,255,.15);color:var(--blue);border:1px solid rgba(74,158,255,.3)}
.ib-approved{background:rgba(0,200,120,.12);color:var(--green);border:1px solid rgba(0,200,120,.25)}
.ib-rejected{background:rgba(100,100,100,.12);color:var(--tx3);border:1px solid rgba(100,100,100,.2)}
.notif-dot{width:8px;height:8px;border-radius:50%;background:var(--red);display:inline-block;margin-left:4px;box-shadow:0 0 6px var(--red);vertical-align:middle;animation:pulse 1.5s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.register-card{width:100%;max-width:460px;background:var(--sf);border:1px solid var(--bd);border-radius:2px;overflow:hidden}
.reg-steps{display:flex;gap:0;border-bottom:1px solid var(--bd)}
.reg-step{flex:1;padding:12px;text-align:center;font-family:'Barlow Condensed',sans-serif;font-size:11px;letter-spacing:1.5px;text-transform:uppercase;color:var(--tx3);border-right:1px solid var(--bd);position:relative}
.reg-step:last-child{border-right:none}
.reg-step.active{color:var(--gold)}
.reg-step.done{color:var(--green)}
.reg-step-num{display:block;font-family:'Bebas Neue',sans-serif;font-size:20px;line-height:1;margin-bottom:2px}
.copy-btn{background:rgba(201,168,76,.1);border:1px solid rgba(201,168,76,.25);color:var(--gold);padding:4px 10px;border-radius:2px;cursor:pointer;font-family:'Barlow Condensed',sans-serif;font-size:10px;letter-spacing:1.5px;transition:all .2s;margin-top:8px;display:inline-block}
.copy-btn:hover{background:rgba(201,168,76,.2)}
.pending-banner{background:rgba(74,158,255,.08);border:1px solid rgba(74,158,255,.2);border-radius:2px;padding:18px;text-align:center;margin-top:16px}
.pending-icon{font-size:36px;display:block;margin-bottom:8px}
.pending-title{font-family:'Bebas Neue',sans-serif;font-size:20px;letter-spacing:3px;color:var(--blue);margin-bottom:6px}
.pending-sub{font-size:12px;color:var(--tx2);line-height:1.6}

@media(max-width:700px){
  .navbar{padding:0 12px;flex-wrap:wrap;height:auto;min-height:52px;padding-top:8px;padding-bottom:8px}
  .nav-tabs{display:none}
  .content{padding:14px 12px}
  .match-body{grid-template-columns:1fr;gap:8px}.team.home,.team.away{text-align:center}
  .t-hero-banner{flex-direction:column;text-align:center;padding:18px;gap:12px}
  .form-grid{grid-template-columns:1fr}.form-grid .full{grid-column:span 1}
  .lb-row{grid-template-columns:36px 1fr 58px}.lb-row .lb-n{display:none}
  .inv-row{grid-template-columns:1fr 90px 80px}
  .inv-row>:nth-child(n+4){display:none}
  .ut-hdr,.ut-row{grid-template-columns:36px 1fr 80px 90px}
  .ut-hdr>:nth-child(n+5),.ut-row>:nth-child(n+5){display:none}
  .comp-grid{grid-template-columns:1fr}
  .mfg{grid-template-columns:1fr}.mfg .afield.full{grid-column:span 1}
}
`;

// ============================================================
// UTILS
// ============================================================
function Toast({message,type,onClose}){
  useEffect(()=>{const t=setTimeout(onClose,3400);return()=>clearTimeout(t);},[onClose]);
  return <div className={"toast"+(type==="err"?" err":"")}>{type==="err"?"⚠ ":"✓ "}{message}</div>;
}
function Loader({text="CARGANDO..."}){
  return <div className="loader-wrap"><div className="loader-logo">⚽</div><div className="loader-txt">{text}</div></div>;
}
function statusLabel(s){return s==="active"?"🟢 En curso":s==="upcoming"?"🟡 Próximo":"⚫ Finalizado";}
function statusClass(s){return s==="active"?"s-act":s==="upcoming"?"s-up":"s-fin";}

// ============================================================
// REGISTER WITH INVITATION CODE
// ============================================================
function RegisterWithCodeScreen({ onBack }) {
  const [step, setStep] = useState(1);
  const [code, setCode]       = useState("");
  const [invitation, setInv]  = useState(null);
  const [username, setUsr]    = useState("");
  const [password, setPwd]    = useState("");
  const [pwd2, setPwd2]       = useState("");
  const [avatar, setAvatar]   = useState("⚽");
  const [err, setErr]         = useState("");
  const [loading, setLoading] = useState(false);

  const handleCheckCode = async () => {
    setErr(""); setLoading(true);
    const invs = await Store.get("db:invitations") || [];
    const inv = invs.find(i => i.code === code.toUpperCase().trim() && i.status === "pending");
    setLoading(false);
    if (!inv) { setErr("Código inválido o ya utilizado."); return; }
    setInv(inv); setStep(2);
  };

  const handleRegister = async () => {
    setErr("");
    if (password !== pwd2) { setErr("Las contraseñas no coinciden"); return; }
    setLoading(true);
    const r = await API.registerWithCode(code, username, password, avatar);
    setLoading(false);
    if (r.error) { setErr(r.error); return; }
    setStep(3);
  };

  return (
    <div className="login-wrap">
      <div className="register-card">
        <div className="login-hdr" style={{padding:"28px 32px 22px"}}>
          <span className="login-logo" style={{fontSize:44}}>📨</span>
          <div className="login-title" style={{fontSize:26}}>UNIRSE CON CÓDIGO</div>
          <div className="login-sub">Ingresá el código que te enviaron</div>
        </div>
        <div className="reg-steps">
          {[{n:1,label:"Código"},{n:2,label:"Datos"},{n:3,label:"Listo"}].map(s=>(
            <div key={s.n} className={"reg-step"+(step===s.n?" active":step>s.n?" done":"")}>
              <span className="reg-step-num">{step>s.n?"✓":s.n}</span>{s.label}
            </div>
          ))}
        </div>
        <div style={{padding:"22px 26px 26px"}}>
          {step===1&&(
            <>
              {err&&<div className="msg-err">{err}</div>}
              <div className="field">
                <label>Código de invitación</label>
                <input value={code} onChange={e=>setCode(e.target.value.toUpperCase())}
                  placeholder="ej: A3B7C9D2" maxLength={8}
                  style={{textAlign:"center",letterSpacing:4,fontSize:18,fontFamily:"Bebas Neue"}}
                  onKeyDown={e=>e.key==="Enter"&&handleCheckCode()}/>
              </div>
              <button className="btn btn-gold btn-full" onClick={handleCheckCode} disabled={loading||!code.trim()}>
                {loading?"VERIFICANDO...":"VERIFICAR CÓDIGO"}
              </button>
              <button className="btn btn-ghost btn-full" style={{marginTop:8}} onClick={onBack}>← Volver al login</button>
            </>
          )}
          {step===2&&invitation&&(
            <>
              <div className="msg-ok" style={{marginBottom:14}}>
                ✓ Invitado por <strong>{invitation.invitedByName}</strong> — <strong>{invitation.tName}</strong>
              </div>
              {err&&<div className="msg-err">{err}</div>}
              <div className="field">
                <label>Nombre de usuario</label>
                <input value={username} onChange={e=>setUsr(e.target.value)} placeholder="ej: jugador99"/>
                <div style={{fontSize:10,color:"var(--tx3)",marginTop:3}}>Solo letras, números y _ (3-20 chars)</div>
              </div>
              <div className="field">
                <label>Contraseña</label>
                <input type="password" value={password} onChange={e=>setPwd(e.target.value)} placeholder="Mínimo 4 caracteres"/>
              </div>
              <div className="field">
                <label>Repetir contraseña</label>
                <input type="password" value={pwd2} onChange={e=>setPwd2(e.target.value)} onKeyDown={e=>e.key==="Enter"&&handleRegister()}/>
              </div>
              <div className="field">
                <label>Avatar</label>
                <div className="avatar-picker">
                  {AVATARS.map(a=>(
                    <button key={a} className={"av-btn"+(avatar===a?" sel":"")} onClick={()=>setAvatar(a)}>{a}</button>
                  ))}
                </div>
              </div>
              <button className="btn btn-gold btn-full" onClick={handleRegister} disabled={loading}>
                {loading?"REGISTRANDO...":"COMPLETAR REGISTRO"}
              </button>
            </>
          )}
          {step===3&&(
            <div className="pending-banner">
              <span className="pending-icon">⏳</span>
              <div className="pending-title">¡REGISTRO ENVIADO!</div>
              <p className="pending-sub">
                Tu solicitud fue enviada al administrador.<br/>
                Una vez aprobada, podrás ingresar con tu usuario y contraseña.<br/><br/>
                <strong style={{color:"var(--gold)"}}>Avisale al admin para que la apruebe.</strong>
              </p>
              <button className="btn btn-ghost" style={{marginTop:14}} onClick={onBack}>← Volver al login</button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ============================================================
// INVITATIONS VIEW
// ============================================================
function InvitationsView({ user, token, showToast, tournaments: tournamentsProp }) {
  const isAdmin = user.role === "admin";
  const [invitations, setInvitations] = useState([]);
  const [tournaments, setTournaments] = useState(tournamentsProp || []);
  const [loading, setLoading]         = useState(true);
  const [selTId, setSelTId]           = useState("");
  const [creating, setCreating]       = useState(false);
  const [copiedId, setCopiedId]       = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    const [tList, invData] = await Promise.all([
      API.getTournaments(),
      isAdmin ? API.getInvitations(user.id, token) : API.getMyInvitations(user.id),
    ]);
    setTournaments(tList);
    if (!selTId && tList.length) setSelTId(tList[0].id);
    const invs = isAdmin ? (invData.invitations || []) : (invData || []);
    setInvitations(invs);
    setLoading(false);
  }, [user.id, token, isAdmin, selTId]);

  useEffect(() => { load(); }, [load]);

  const handleCreate = async () => {
    if (!selTId) { showToast("Seleccioná un torneo", "err"); return; }
    setCreating(true);
    const r = await API.createInvitation(user.id, selTId);
    setCreating(false);
    if (r.error) { showToast(r.error, "err"); return; }
    showToast("¡Código generado! Compartilo con tu amigo.");
    load();
  };

  const handleCopy = (inv) => {
    const text = `¡Te invito a jugar Super Campeones!\n\nTorneo: ${inv.tName}\nCódigo: ${inv.code}\n\nIngresá a la app y usá "Tengo un código de invitación".`;
    navigator.clipboard?.writeText(text).catch(()=>{});
    setCopiedId(inv.id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleApprove = async (invId) => {
    const r = await API.approveInvitation(user.id, invId, token);
    if (r.success) { showToast(`✅ Usuario "${r.user.username}" creado y aprobado`); load(); }
    else showToast(r.error, "err");
  };

  const handleReject = async (invId) => {
    const r = await API.rejectInvitation(user.id, invId, token);
    if (r.success) { showToast("Invitación rechazada"); load(); }
    else showToast(r.error, "err");
  };

  const handleCancel = async (invId) => {
    const r = await API.cancelInvitation(user.id, invId);
    if (r.success) { showToast("Invitación cancelada"); load(); }
    else showToast(r.error, "err");
  };

  const invBadge = (s) => {
    const map = { pending:"ib-pending", registered:"ib-registered", approved:"ib-approved", rejected:"ib-rejected" };
    const lbl = { pending:"⏳ Pendiente", registered:"📋 Con datos", approved:"✅ Aprobada", rejected:"❌ Rechazada" };
    return <span className={"inv-badge "+(map[s]||"")}>{lbl[s]||s}</span>;
  };

  const pending = invitations.filter(i => i.status === "registered");

  return (
    <div>
      {isAdmin && pending.length > 0 && (
        <div className="msg-warn" style={{marginBottom:16,display:"flex",alignItems:"center",gap:10}}>
          <span style={{fontSize:18}}>🔔</span>
          <strong>{pending.length}</strong>&nbsp;solicitud{pending.length>1?"es":""} esperando aprobación
        </div>
      )}

      {/* Create invitation */}
      <div style={{background:"var(--sf2)",border:"1px solid var(--bd)",borderRadius:2,padding:16,marginBottom:20}}>
        <div style={{fontFamily:"Barlow Condensed",fontSize:11,letterSpacing:2,textTransform:"uppercase",color:"var(--tx3)",marginBottom:12}}>
          📨 Invitar a un amigo
        </div>
        <div style={{display:"flex",gap:10,alignItems:"flex-end",flexWrap:"wrap"}}>
          <div style={{flex:1,minWidth:180}}>
            <label style={{display:"block",fontSize:9,letterSpacing:2,textTransform:"uppercase",color:"var(--tx3)",fontFamily:"Barlow Condensed",marginBottom:5}}>Torneo</label>
            <select className="ap-select" style={{width:"100%"}} value={selTId} onChange={e=>setSelTId(e.target.value)}>
              <option value="">— Seleccioná un torneo —</option>
              {(tournaments||[]).map(t=><option key={t.id} value={t.id}>{t.logo} {t.name}</option>)}
            </select>
          </div>
          <button className="btn btn-gold" onClick={handleCreate} disabled={creating||!selTId}>
            {creating?"GENERANDO...":"+ GENERAR CÓDIGO"}
          </button>
        </div>
        <div style={{fontSize:10,color:"var(--tx3)",marginTop:8,fontFamily:"Barlow Condensed",letterSpacing:1}}>
          Se genera un código único que tu amigo usará para registrarse. Un admin deberá aprobarlo.
        </div>
      </div>

      {/* List */}
      {loading ? <div className="empty">Cargando...</div> : invitations.length === 0 ? (
        <div className="empty">Sin invitaciones todavía</div>
      ) : (
        <div className="inv-table">
          <div className="inv-row hdr">
            <div>Torneo · Creada por</div>
            <div>Código</div>
            <div>Estado</div>
            <div>Usuario solicitado</div>
            <div>Acciones</div>
          </div>
          {invitations.slice().reverse().map(inv=>(
            <div key={inv.id} className="inv-row" style={inv.status==="registered"&&isAdmin?{background:"rgba(74,158,255,.04)",borderLeft:"2px solid var(--blue)"}:{}}>
              <div>
                <div style={{fontSize:12,fontWeight:500}}>{inv.tName}</div>
                <div style={{fontSize:10,color:"var(--tx3)",fontFamily:"Barlow Condensed",letterSpacing:1}}>
                  {inv.invitedByName} · {inv.createdAt?.split("T")[0]}
                </div>
              </div>
              <div>
                <span style={{fontFamily:"Bebas Neue",fontSize:inv.status==="pending"?16:13,letterSpacing:3,color:inv.status==="pending"?"var(--gold)":"var(--tx3)"}}>
                  {inv.code}
                </span>
              </div>
              <div>{invBadge(inv.status)}</div>
              <div style={{fontSize:11,color:inv.newUsername?"var(--tx2)":"var(--tx3)"}}>
                {inv.newUsername
                  ? <span style={{display:"flex",alignItems:"center",gap:5}}><span style={{fontSize:15}}>{inv.newAvatar}</span>{inv.newUsername}</span>
                  : "—"}
              </div>
              <div style={{display:"flex",gap:5,flexWrap:"wrap"}}>
                {inv.status==="pending"&&(
                  <>
                    <button className="copy-btn" onClick={()=>handleCopy(inv)}>{copiedId===inv.id?"✓ OK":"📋 Copiar"}</button>
                    {(inv.invitedBy===user.id||isAdmin)&&(
                      <button className="icon-btn danger" title="Cancelar" onClick={()=>handleCancel(inv.id)}>✕</button>
                    )}
                  </>
                )}
                {isAdmin&&inv.status==="registered"&&(
                  <>
                    <button className="icon-btn success" title="Aprobar" onClick={()=>handleApprove(inv.id)}>✅</button>
                    <button className="icon-btn danger"  title="Rechazar" onClick={()=>handleReject(inv.id)}>❌</button>
                  </>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ============================================================
// LOGIN
// ============================================================
function LoginScreen({onLogin, onRegister}){
  const [u,setU]=useState(""); const [pwd,setPwd]=useState(""); const [err,setErr]=useState(""); const [loading,setL]=useState(false);
  const go=async(name,pass)=>{
    setErr(""); setL(true);
    const r=await API.login(name||u.trim(), pass||pwd);
    setL(false);
    if(r.error) setErr(r.error); else onLogin(r.token,r.user);
  };
  return(
    <div className="login-wrap">
      <div className="login-card">
        <div className="login-hdr">
          <span className="login-logo">🏆</span>
          <div className="login-title">SUPER CAMPEONES</div>
          <div className="login-sub">Pronosticá · Competí · Ganá</div>
        </div>
        <div className="login-body">
          {err&&<div className="msg-err">⚠ {err}</div>}
          <div className="field"><label>Usuario</label>
            <input value={u} onChange={e=>setU(e.target.value)} placeholder="Tu nombre de usuario"
              onKeyDown={e=>e.key==="Enter"&&go()} autoComplete="username"/>
          </div>
          <div className="field"><label>Contraseña</label>
            <input type="password" value={pwd} onChange={e=>setPwd(e.target.value)} placeholder="••••••••"
              onKeyDown={e=>e.key==="Enter"&&go()} autoComplete="current-password"/>
          </div>
          <button className="btn btn-gold btn-full" onClick={()=>go()} disabled={loading}>
            {loading?"VERIFICANDO...":"INGRESAR"}
          </button>
          {/* Invitation code entry */}
          <button className="btn btn-ghost btn-full" style={{marginTop:10}} onClick={onRegister}>
            📨 Tengo un código de invitación
          </button>
          <div className="demo-box">
            <p><span className="db-dot"></span>Cuentas demo (cualquier contraseña)</p>
            {["admin","diego10","leo30","cr7fan"].map(n=>(
              <button key={n} className="demo-btn" onClick={()=>{setU(n);setPwd("demo");go(n,"demo");}}>{n}</button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ============================================================
// USER MANAGEMENT VIEW
// ============================================================
function ConfirmModal({title,message,onConfirm,onCancel,danger=true}){
  return(
    <div className="modal-overlay" onClick={e=>{if(e.target===e.currentTarget)onCancel();}}>
      <div className="modal" style={{maxWidth:380}}>
        <div className="modal-body">
          <div className="confirm-modal">
            <h3 style={{color:danger?"#ff8888":"var(--gold)"}}>{title}</h3>
            <p>{message}</p>
          </div>
        </div>
        <div className="modal-footer">
          <button className="btn btn-ghost" onClick={onCancel}>Cancelar</button>
          <button className={`btn ${danger?"btn-red":"btn-gold"}`} onClick={onConfirm}>Confirmar</button>
        </div>
      </div>
    </div>
  );
}

function UserFormModal({editUser, token, currentUserId, onClose, onSaved, showToast}){
  const isEdit = !!editUser;
  const [form,setForm]=useState({
    username: editUser?.username||"",
    password: "",
    role: editUser?.role||"user",
    avatar: editUser?.avatar||"⚽",
    active: editUser?.active!==undefined ? editUser.active : true,
  });
  const [err,setErr]=useState("");
  const [saving,setSaving]=useState(false);
  const upd=k=>e=>setForm(f=>({...f,[k]:e.target.type==="checkbox"?e.target.checked:e.target.value}));

  const handleSave=async()=>{
    setErr(""); setSaving(true);
    let r;
    if(isEdit){
      const fields={role:form.role,avatar:form.avatar,active:form.active};
      if(form.password) fields.password=form.password;
      r=await API.adminUpdateUser(currentUserId, editUser.id, fields, token);
    } else {
      r=await API.adminCreateUser(currentUserId, form, token);
    }
    setSaving(false);
    if(r.error){setErr(r.error);return;}
    showToast(isEdit?"Usuario actualizado":"Usuario creado");
    onSaved(r.user);
    onClose();
  };

  return(
    <div className="modal-overlay" onClick={e=>{if(e.target===e.currentTarget)onClose();}}>
      <div className="modal">
        <div className="modal-hdr">
          <div className="modal-title">{isEdit?"EDITAR USUARIO":"NUEVO USUARIO"}</div>
          <button className="btn btn-ghost" style={{padding:"3px 9px",fontSize:15}} onClick={onClose}>✕</button>
        </div>
        <div className="modal-body">
          {err&&<div className="msg-err">{err}</div>}
          <div className="form-grid">
            <div className="field full">
              <label>Nombre de usuario {isEdit&&<span style={{color:"var(--tx3)"}}>(no editable)</span>}</label>
              <input value={form.username} onChange={upd("username")} placeholder="ej: jugador99"
                disabled={isEdit} style={isEdit?{opacity:.5}:{}}/>
              {!isEdit&&<div style={{fontSize:10,color:"var(--tx3)",marginTop:4}}>Solo letras, números y _ (3-20 caracteres)</div>}
            </div>
            <div className="field full">
              <label>{isEdit?"Nueva contraseña (dejar vacío para no cambiar)":"Contraseña *"}</label>
              <input type="password" value={form.password} onChange={upd("password")}
                placeholder={isEdit?"••••••••  (sin cambios)":"Mínimo 4 caracteres"}/>
            </div>
            <div className="field">
              <label>Rol</label>
              <select value={form.role} onChange={upd("role")}
                disabled={isEdit&&editUser.id==="u1"} style={isEdit&&editUser.id==="u1"?{opacity:.5}:{}}>
                <option value="user">👤 Jugador</option>
                <option value="admin">🔑 Administrador</option>
              </select>
            </div>
            <div className="field">
              <label>Estado</label>
              <select value={form.active?"active":"inactive"} onChange={e=>setForm(f=>({...f,active:e.target.value==="active"}))}>
                <option value="active">🟢 Activo</option>
                <option value="inactive">🔴 Desactivado</option>
              </select>
            </div>
          </div>
          <div className="field" style={{marginTop:8}}>
            <label>Avatar</label>
            <div className="avatar-picker">
              {AVATARS.map(a=>(
                <button key={a} className={"av-btn"+(form.avatar===a?" sel":"")} onClick={()=>setForm(f=>({...f,avatar:a}))}>{a}</button>
              ))}
            </div>
          </div>
        </div>
        <div className="modal-footer">
          <button className="btn btn-ghost" onClick={onClose}>Cancelar</button>
          <button className="btn btn-gold" onClick={handleSave} disabled={saving}>
            {saving?"GUARDANDO...":(isEdit?"GUARDAR CAMBIOS":"CREAR USUARIO")}
          </button>
        </div>
      </div>
    </div>
  );
}

function UsersView({user, token, showToast}){
  const [innerTab, setInnerTab] = useState("users"); // "users" | "invitations"
  const [users,setUsers]=useState([]);
  const [tournaments,setTournaments]=useState([]);
  const [loading,setLoading]=useState(true);
  const [showForm,setShowForm]=useState(false);
  const [editUser,setEditUser]=useState(null);
  const [confirmDel,setConfirmDel]=useState(null);
  const [confirmToggle,setConfirmToggle]=useState(null);
  const [pendingCount,setPendingCount]=useState(0);

  const load=useCallback(async()=>{
    const [r, t, invs] = await Promise.all([
      API.getUsers(user.id, token),
      API.getTournaments(),
      API.getInvitations(user.id, token),
    ]);
    if(r.users) setUsers(r.users);
    setTournaments(t);
    if(invs.invitations) setPendingCount(invs.invitations.filter(i=>i.status==="registered").length);
    setLoading(false);
  },[user.id,token]);

  useEffect(()=>{load();},[load]);

  const handleDelete=async()=>{
    const r=await API.adminDeleteUser(user.id,confirmDel.id,token);
    setConfirmDel(null);
    if(r.success){showToast("Usuario eliminado");load();}
    else showToast(r.error,"err");
  };

  const handleToggle=async()=>{
    const r=await API.adminUpdateUser(user.id,confirmToggle.id,{active:!confirmToggle.active},token);
    setConfirmToggle(null);
    if(r.success){showToast(r.user.active?"Usuario activado":"Usuario desactivado");load();}
    else showToast(r.error,"err");
  };

  const totalActive=users.filter(u=>u.active&&u.role==="user").length;
  const totalAdmins=users.filter(u=>u.role==="admin").length;

  if(loading) return <div className="content"><div className="empty">Cargando...</div></div>;

  return(
    <div className="content">
      <div style={{display:"flex",alignItems:"flex-start",justifyContent:"space-between",marginBottom:20,flexWrap:"wrap",gap:12}}>
        <div>
          <div className="sec-title">GESTIÓN DE USUARIOS</div>
          <div className="sec-sub"><span className="db-dot"></span>{users.length} usuarios · {totalActive} jugadores activos</div>
        </div>
        {innerTab==="users"&&(
          <button className="btn btn-gold" onClick={()=>{setEditUser(null);setShowForm(true);}}>+ NUEVO USUARIO</button>
        )}
      </div>

      {/* Inner tabs */}
      <div className="ap-tabs" style={{marginBottom:20}}>
        <button className={"ap-tab"+(innerTab==="users"?" active":"")} onClick={()=>setInnerTab("users")}>
          👤 Usuarios
        </button>
        <button className={"ap-tab"+(innerTab==="invitations"?" active":"")} onClick={()=>{setInnerTab("invitations");load();}}>
          📨 Invitaciones
          {pendingCount>0&&<span className="notif-dot"/>}
        </button>
      </div>

      {/* USERS TAB */}
      {innerTab==="users"&&(
        <>
          {/* Stats */}
          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(130px,1fr))",gap:10,marginBottom:20}}>
            {[
              {label:"Total",     value:users.length,                            color:"var(--tx)"},
              {label:"Jugadores", value:users.filter(u=>u.role==="user").length, color:"var(--blue)"},
              {label:"Admins",    value:totalAdmins,                             color:"#ff8888"},
              {label:"Activos",   value:users.filter(u=>u.active).length,        color:"var(--green)"},
              {label:"Inactivos", value:users.filter(u=>!u.active).length,       color:"var(--tx3)"},
            ].map(s=>(
              <div key={s.label} style={{background:"var(--sf)",border:"1px solid var(--bd)",borderRadius:2,padding:"11px 14px"}}>
                <div style={{fontFamily:"Bebas Neue",fontSize:26,color:s.color,lineHeight:1}}>{s.value}</div>
                <div style={{fontSize:9,color:"var(--tx3)",fontFamily:"Barlow Condensed",letterSpacing:2,textTransform:"uppercase",marginTop:3}}>{s.label}</div>
              </div>
            ))}
          </div>

          <div className="users-table">
            <div className="ut-hdr">
              <div></div><div>Usuario</div><div>Rol</div><div>Estado</div><div>Alta</div><div>Acciones</div>
            </div>
            {users.length===0?(
              <div className="empty">No hay usuarios</div>
            ):users.map(u=>(
              <div key={u.id} className="ut-row">
                <div className="ut-avatar">{u.avatar}</div>
                <div>
                  <div className="ut-name">{u.username}</div>
                  {u.id===user.id&&<div style={{fontSize:9,color:"var(--gold)",fontFamily:"Barlow Condensed",letterSpacing:1}}>TÚ</div>}
                  {u.invitedByName&&<div style={{fontSize:9,color:"var(--tx3)",fontFamily:"Barlow Condensed",letterSpacing:1}}>Invitado por {u.invitedByName}</div>}
                </div>
                <div><span className={"role-badge "+(u.role==="admin"?"rb-admin":"rb-user")}>{u.role==="admin"?"Admin":"Jugador"}</span></div>
                <div><span className={"active-badge "+(u.active?"ab-on":"ab-off")}>{u.active?"Activo":"Inactivo"}</span></div>
                <div className="ut-date">{u.createdAt||"-"}</div>
                <div className="ut-actions">
                  <button className="icon-btn" title="Editar" onClick={()=>{setEditUser(u);setShowForm(true);}}>✏️</button>
                  {u.id!=="u1"&&(
                    <button className={"icon-btn "+(u.active?"danger":"success")} title={u.active?"Desactivar":"Activar"} onClick={()=>setConfirmToggle(u)}>
                      {u.active?"🔒":"🔓"}
                    </button>
                  )}
                  {u.id!=="u1"&&u.id!==user.id&&(
                    <button className="icon-btn danger" title="Eliminar" onClick={()=>setConfirmDel(u)}>🗑️</button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      {/* INVITATIONS TAB */}
      {innerTab==="invitations"&&(
        <InvitationsView user={user} token={token} showToast={showToast} tournaments={tournaments}/>
      )}

      {/* Modals */}
      {showForm&&(
        <UserFormModal editUser={editUser} token={token} currentUserId={user.id}
          onClose={()=>{setShowForm(false);setEditUser(null);}}
          onSaved={()=>load()} showToast={showToast}/>
      )}
      {confirmDel&&(
        <ConfirmModal title="¿ELIMINAR USUARIO?"
          message={`¿Estás seguro que querés eliminar a "${confirmDel.username}"? Esta acción no se puede deshacer.`}
          onConfirm={handleDelete} onCancel={()=>setConfirmDel(null)}/>
      )}
      {confirmToggle&&(
        <ConfirmModal title={confirmToggle.active?"¿DESACTIVAR USUARIO?":"¿ACTIVAR USUARIO?"}
          message={confirmToggle.active
            ? `"${confirmToggle.username}" no podrá ingresar hasta que lo reactives.`
            : `"${confirmToggle.username}" podrá volver a ingresar al sistema.`}
          danger={confirmToggle.active}
          onConfirm={handleToggle} onCancel={()=>setConfirmToggle(null)}/>
      )}
    </div>
  );
}

// ============================================================
// CREATE TOURNAMENT MODAL
// ============================================================
const LOGOS=["🌍","🌎","🌏","⚽","🏆","⭐","🥇","🎯"];
const FIFA_COMPS=Object.entries(FIFA_API.COMPETITIONS);

function CreateTournamentModal({token,user,onClose,onCreated,showToast}){
  const [mode,setMode]=useState("manual");
  const [form,setForm]=useState({name:"",shortName:"",region:"Global",status:"upcoming",logo:"🏆",startDate:"",endDate:"",groups:"A,B,C,D,E,F,G,H"});
  const [saving,setSaving]=useState(false);
  const [formErr,setFormErr]=useState("");
  const [selComp,setSelComp]=useState(null);
  const [selCompId,setSelCompId]=useState(null);
  const [query,setQuery]=useState("");
  const [results,setResults]=useState([]);
  const [searching,setSearching]=useState(false);
  const [searchErr,setSearchErr]=useState("");
  const [selSeason,setSelSeason]=useState(null);
  const [corsBlocked,setCorsBlocked]=useState(false);
  const upd=k=>e=>setForm(f=>({...f,[k]:e.target.value}));

  const handleCreate=async()=>{
    setFormErr(""); setSaving(true);
    const r=await API.adminCreateTournament(user.id,{...form,source:"manual"},token);
    setSaving(false);
    if(r.error){setFormErr(r.error);return;}
    showToast("Torneo creado"); onCreated(); onClose();
  };

  const handleSearch=async()=>{
    if(!selComp||!query.trim()) return;
    setSearching(true); setSearchErr(""); setResults([]); setCorsBlocked(false);
    const r=await FIFA_API.searchSeasons(query);
    setSearching(false);
    if(r.error){setCorsBlocked(true);setSearchErr(r.error);return;}
    const list=(r.Results||r||[]);
    setResults(list);
    if(!list.length) setSearchErr("Sin resultados.");
  };

  const handleImport=async()=>{
    if(!selSeason) return;
    setSaving(true);
    const d={name:selSeason.Name?.[0]?.Description||query,shortName:selSeason.Name?.[0]?.Description||query,region:"Global",status:"upcoming",logo:"🌍",startDate:selSeason.StartDate?.split("T")[0]||"",endDate:selSeason.EndDate?.split("T")[0]||"",groups:"A,B,C,D,E,F,G,H",source:"fifa_api",fifaCompId:selCompId,fifaSeasonId:selSeason.IdSeason};
    const cr=await API.adminCreateTournament(user.id,d,token);
    if(cr.error){setSaving(false);setFormErr(cr.error);return;}
    const ir=await API.adminImportFromFIFA(user.id,cr.tournament.id,selCompId,selSeason.IdSeason,token);
    setSaving(false);
    if(ir.error){setCorsBlocked(ir.corsBlocked);setFormErr("Torneo creado sin partidos: "+ir.error);showToast("Torneo creado (sin partidos)","warn");onCreated();onClose();return;}
    showToast(`Importado: ${ir.count} partidos`); onCreated(); onClose();
  };

  return(
    <div className="modal-overlay" onClick={e=>{if(e.target===e.currentTarget)onClose();}}>
      <div className="modal modal-lg">
        <div className="modal-hdr">
          <div className="modal-title">NUEVO TORNEO</div>
          <button className="btn btn-ghost" style={{padding:"3px 9px",fontSize:15}} onClick={onClose}>✕</button>
        </div>
        <div className="modal-body">
          <div className="tab-switcher">
            <button className={"tab-sw-btn"+(mode==="manual"?" active":"")} onClick={()=>setMode("manual")}>✏️ Carga Manual</button>
            <button className={"tab-sw-btn"+(mode==="fifa"?" active":"")} onClick={()=>setMode("fifa")}>🌐 FIFA API</button>
          </div>
          {mode==="manual"&&(
            <>
              {formErr&&<div className="msg-err">{formErr}</div>}
              <div className="form-grid">
                <div className="field full"><label>Nombre del torneo *</label><input value={form.name} onChange={upd("name")} placeholder="ej: Copa América 2027"/></div>
                <div className="field"><label>Nombre corto</label><input value={form.shortName} onChange={upd("shortName")} placeholder="ej: Copa América"/></div>
                <div className="field"><label>Región</label>
                  <select value={form.region} onChange={upd("region")}>
                    {["Global","CONMEBOL","UEFA","CONCACAF","CAF","AFC","OFC"].map(r=><option key={r}>{r}</option>)}
                  </select>
                </div>
                <div className="field"><label>Fecha inicio *</label><input type="date" value={form.startDate} onChange={upd("startDate")}/></div>
                <div className="field"><label>Fecha fin *</label><input type="date" value={form.endDate} onChange={upd("endDate")}/></div>
                <div className="field"><label>Estado</label>
                  <select value={form.status} onChange={upd("status")}>
                    <option value="upcoming">🟡 Próximo</option><option value="active">🟢 En curso</option><option value="finished">⚫ Finalizado</option>
                  </select>
                </div>
                <div className="field"><label>Grupos (separados por coma)</label><input value={form.groups} onChange={upd("groups")} placeholder="A,B,C,D"/></div>
              </div>
              <div className="field" style={{marginTop:10}}><label>Ícono</label>
                <div style={{display:"flex",gap:6,flexWrap:"wrap",marginTop:4}}>
                  {LOGOS.map(l=>(
                    <button key={l} onClick={()=>setForm(f=>({...f,logo:l}))}
                      style={{fontSize:24,background:form.logo===l?"rgba(201,168,76,.2)":"var(--bg)",border:form.logo===l?"1px solid var(--gold)":"1px solid var(--bd)",borderRadius:4,padding:"4px 8px",cursor:"pointer"}}>
                      {l}
                    </button>
                  ))}
                </div>
              </div>
            </>
          )}
          {mode==="fifa"&&(
            <>
              <div className="fifa-sec">
                <div className="fifa-sec-title">🌐 API Oficial FIFA — givevoicetofootball.fifa.com</div>
                <p style={{fontSize:11,color:"var(--tx2)",marginBottom:12,lineHeight:1.6}}>Seleccioná una competencia y buscá la edición para importar torneos y partidos oficiales.</p>
                <label className="ap-label" style={{marginBottom:8}}>Competencia</label>
                <div className="comp-grid">
                  {FIFA_COMPS.map(([name,id])=>(
                    <button key={id} className={"comp-btn"+(selCompId===id?" sel":"")} onClick={()=>{setSelComp(name);setSelCompId(id);setQuery(name);}}>
                      <div style={{fontWeight:600,fontSize:11}}>{name}</div>
                      <div style={{fontSize:9,color:"var(--tx3)"}}>ID: {id}</div>
                    </button>
                  ))}
                </div>
                {selComp&&(
                  <div style={{display:"flex",gap:8,alignItems:"flex-end"}}>
                    <div style={{flex:1}}>
                      <label className="ap-label">Buscar edición</label>
                      <input className="ap-input" style={{width:"100%"}} value={query} onChange={e=>setQuery(e.target.value)}
                        placeholder={`ej: ${selComp} 2022`} onKeyDown={e=>e.key==="Enter"&&handleSearch()}/>
                    </div>
                    <button className="btn btn-blue" onClick={handleSearch} disabled={searching}>{searching?"BUSCANDO...":"BUSCAR"}</button>
                  </div>
                )}
              </div>
              {searchErr&&!corsBlocked&&<div className="msg-err">{searchErr}</div>}
              {corsBlocked&&(
                <div className="cors-box">
                  <div className="cors-title">⚠ CORS — requiere backend proxy</div>
                  <p style={{fontSize:11,color:"var(--tx2)",marginBottom:10,lineHeight:1.6}}>La API de FIFA bloquea llamadas directas desde el navegador. Funciona desde un servidor backend (Node.js, etc.).</p>
                  <div className="cors-code">
                    <div>🔍 <code>GET /api/v1/seasons/search?name=FIFA+World+Cup</code></div>
                    <div>📅 <code>GET /api/v1/calendar/matches?idSeason=X&idCompetition=Y</code></div>
                    <div>📖 <code>givevoicetofootball.fifa.com/ApiFdcpSwagger</code></div>
                  </div>
                  <button className="btn btn-gold" style={{marginTop:10,fontSize:11,padding:"6px 13px"}} onClick={()=>{setMode("manual");setCorsBlocked(false);}}>Cargar manualmente →</button>
                </div>
              )}
              {results.length>0&&(
                <>
                  <label className="ap-label" style={{marginBottom:6}}>Seleccioná la edición</label>
                  <div className="search-results">
                    {results.map(s=>(
                      <div key={s.IdSeason} className="sri"
                        style={{background:selSeason?.IdSeason===s.IdSeason?"rgba(201,168,76,.08)":"",borderLeft:selSeason?.IdSeason===s.IdSeason?"2px solid var(--gold)":"2px solid transparent"}}
                        onClick={()=>setSelSeason(s)}>
                        <div><div style={{fontSize:13,fontWeight:500}}>{s.Name?.[0]?.Description||s.IdSeason}</div><div style={{fontSize:11,color:"var(--tx3)",fontFamily:"Barlow Condensed"}}>{s.StartDate?.split("T")[0]} — {s.EndDate?.split("T")[0]}</div></div>
                        <div style={{fontSize:10,color:"var(--tx3)"}}>ID: {s.IdSeason}</div>
                      </div>
                    ))}
                  </div>
                  {selSeason&&<button className="btn btn-gold" style={{marginTop:12,width:"100%",justifyContent:"center"}} onClick={handleImport} disabled={saving}>{saving?"IMPORTANDO...":"IMPORTAR TORNEO + PARTIDOS"}</button>}
                </>
              )}
              {formErr&&<div className="msg-err" style={{marginTop:10}}>{formErr}</div>}
            </>
          )}
        </div>
        {mode==="manual"&&(
          <div className="modal-footer">
            <button className="btn btn-ghost" onClick={onClose}>Cancelar</button>
            <button className="btn btn-gold" onClick={handleCreate} disabled={saving}>{saving?"CREANDO...":"CREAR TORNEO"}</button>
          </div>
        )}
      </div>
    </div>
  );
}

// ============================================================
// TOURNAMENT LOBBY
// ============================================================
function TournamentLobby({user,token,onSelect,showToast}){
  const [tournaments,setTournaments]=useState([]);
  const [loading,setLoading]=useState(true);
  const [showCreate,setShowCreate]=useState(false);
  const [confirmDel,setConfirmDel]=useState(null);
  const isAdmin=user.role==="admin";

  const load=useCallback(async()=>{
    const t=await API.getTournaments();setTournaments(t);setLoading(false);
  },[]);
  useEffect(()=>{load();},[load]);

  const handleDelete=async()=>{
    const r=await API.adminDeleteTournament(user.id,confirmDel.id,token);
    setConfirmDel(null);
    if(r.success){showToast("Torneo eliminado");load();}else showToast(r.error,"err");
  };

  if(loading) return <div className="content"><div className="empty">Cargando...</div></div>;

  return(
    <div className="content">
      <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:22,flexWrap:"wrap",gap:12}}>
        <div>
          <div className="sec-title">TORNEOS</div>
          <div className="sec-sub"><span className="db-dot"></span>{tournaments.length} torneo{tournaments.length!==1?"s":""} disponibles</div>
        </div>
        {isAdmin&&<button className="btn btn-gold" onClick={()=>setShowCreate(true)}>+ NUEVO TORNEO</button>}
      </div>
      {tournaments.length===0?(
        <div className="empty">{isAdmin?"Sin torneos. Creá uno.":"Sin torneos disponibles."}</div>
      ):(
        <div className="t-grid">
          {tournaments.map(t=>(
            <div key={t.id} className="t-card" onClick={()=>onSelect(t)}>
              <div className="t-card-top">
                <div className="t-card-logo">{t.logo}</div>
                <div>
                  <div className="t-card-name">{t.name}</div>
                  <div className="t-card-meta">{t.region} · {t.startDate} → {t.endDate}</div>
                </div>
              </div>
              <div className="t-card-bot">
                <div style={{display:"flex",gap:6,alignItems:"center"}}>
                  <span className={"status-badge "+statusClass(t.status)}>{statusLabel(t.status)}</span>
                  <span className={"source-chip "+(t.source==="fifa_api"?"src-fifa":"src-manual")}>{t.source==="fifa_api"?"🌐 FIFA":"✏ Manual"}</span>
                </div>
                <div style={{display:"flex",alignItems:"center",gap:8}}>
                  <span style={{fontSize:10,color:"var(--tx3)",fontFamily:"Barlow Condensed"}}>{(t.groups||[]).length} grupos</span>
                  {isAdmin&&t.id!=="t1"&&(
                    <button onClick={e=>{e.stopPropagation();setConfirmDel(t);}}
                      style={{background:"rgba(255,68,68,.12)",border:"1px solid rgba(255,68,68,.25)",color:"#ff8888",padding:"2px 7px",borderRadius:2,cursor:"pointer",fontSize:10,fontFamily:"Barlow Condensed"}}>✕</button>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
      {showCreate&&<CreateTournamentModal token={token} user={user} showToast={showToast} onClose={()=>setShowCreate(false)} onCreated={load}/>}
      {confirmDel&&<ConfirmModal title="¿ELIMINAR TORNEO?" message={`¿Eliminar "${confirmDel.name}"? Se perderán todos los pronósticos asociados.`} onConfirm={handleDelete} onCancel={()=>setConfirmDel(null)}/>}
    </div>
  );
}

// ============================================================
// MATCH CARD
// ============================================================
function MatchCard({match,tId,userId,token,isAdmin,onSave,onAdminSave}){
  const [h,setH]=useState(match.myPrediction?.homeScore?.toString()??"");
  const [a,setA]=useState(match.myPrediction?.awayScore?.toString()??"");
  const [saved,setSaved]=useState(!!match.myPrediction);
  const [saving,setSaving]=useState(false);
  const [ah,setAH]=useState(match.homeScore?.toString()??"");
  const [aa,setAA]=useState(match.awayScore?.toString()??"");
  const [as2,setAS]=useState(false);
  const pts=match.myPrediction?.points;
  return(
    <div className="match-card">
      <div className="match-hdr">
        <span>{match.stage} — {match.date} {match.time}</span>
        <span className={"status-badge "+statusClass(match.status)}>{match.status==="finished"?"Finalizado":match.status==="active"?"En curso":"Pendiente"}</span>
      </div>

      {/* ── DESKTOP: Local | Centro | Visitante en una fila ───── */}
      <div className="match-body match-body-desktop">
        <div className={"team home"+(match.homeTeam?.startsWith("TBD:")?" tbd":"")}>
          {match.homeTeam?.startsWith("TBD:") ? "❓ "+match.homeTeam.slice(4) : match.homeTeam}
        </div>
        <div className="match-center">
          {match.status==="finished"?(
            <div className="score-fin"><span>{match.homeScore}</span><span className="score-sep">–</span><span>{match.awayScore}</span></div>
          ):match.homeTeam?.startsWith("TBD:")||match.awayTeam?.startsWith("TBD:")?(
            <div className="tbd-match-note">Equipos por definirse</div>
          ):(
            <div className="score-row">
              <input className="sinput" type="number" min="0" max="30" value={h} onChange={e=>{setH(e.target.value);setSaved(false)}}/>
              <span style={{color:"var(--tx3)",fontFamily:"Bebas Neue",fontSize:17}}>–</span>
              <input className="sinput" type="number" min="0" max="30" value={a} onChange={e=>{setA(e.target.value);setSaved(false)}}/>
            </div>
          )}
          {match.myPrediction&&(
            <div style={{textAlign:"center",marginTop:5,display:"flex",justifyContent:"center",flexWrap:"wrap",gap:4}}>
              <span className="pred-badge">Pronóstico: {match.myPrediction.homeScore}–{match.myPrediction.awayScore}</span>
              {match.status==="finished"&&pts!==undefined&&<span className="pts-badge">+{pts}pts</span>}
            </div>
          )}
        </div>
        <div className={"team away"+(match.awayTeam?.startsWith("TBD:")?" tbd":"")}>
          {match.awayTeam?.startsWith("TBD:") ? "❓ "+match.awayTeam.slice(4) : match.awayTeam}
        </div>
      </div>

      {/* Botón GUARDAR — fila propia debajo del marcador */}
      {match.status!=="finished"&&!match.homeTeam?.startsWith("TBD:")&&!match.awayTeam?.startsWith("TBD:")&&(
        <div className="save-row">
          <button className={"pred-btn"+(saved?" saved":"")} disabled={saving}
            onClick={async()=>{if(h===""||a==="")return;setSaving(true);const r=await onSave(match.id,h,a);setSaving(false);if(r?.success)setSaved(true);}}>
            {saving?"...":saved?"✓ GUARDADO":"GUARDAR PRONÓSTICO"}
          </button>
        </div>
      )}

      {isAdmin&&match.status!=="finished"&&(
        <div className="admin-footer">
          <span style={{fontSize:9,letterSpacing:2,color:"#ff8888",fontFamily:"Barlow Condensed",textTransform:"uppercase"}}>Admin resultado:</span>
          <input className="ainput" type="number" min="0" max="30" value={ah} onChange={e=>setAH(e.target.value)}/>
          <span style={{color:"var(--tx3)"}}>–</span>
          <input className="ainput" type="number" min="0" max="30" value={aa} onChange={e=>setAA(e.target.value)}/>
          <button className="ares-btn" disabled={as2} onClick={async()=>{setAS(true);await onAdminSave(match.id,ah,aa);setAS(false);}}>
            {as2?"...":"GUARDAR"}
          </button>
        </div>
      )}
    </div>
  );
}

// ============================================================
// MATCHES VIEW
// ============================================================
function MatchesView({tournament,user,token,showToast,onPointsUpdate}){
  const [matches,setMatches]=useState([]);
  const [group,setGroup]=useState("ALL");
  const [loading,setLoading]=useState(true);
  const [apTab,setApTab]=useState("status");
  const [editStatus,setEditStatus]=useState(tournament.status);
  const [savingStatus,setSavingStatus]=useState(false);
  const [mForm,setMForm]=useState({
    homeTeam:"",awayTeam:"",group:tournament.groups?.[0]||"A",date:"",time:"18:00",stage:"",
    nextMatchWinnerId:"",nextMatchWinnerSlot:"home",
    nextMatchLoserId:"", nextMatchLoserSlot:"home",
  });
  const [addingMatch,setAddingMatch]=useState(false);
  const [matchErr,setMatchErr]=useState("");
  const isAdmin=user.role==="admin";

  const load=useCallback(async()=>{
    const m=await API.getMatches(tournament.id,user.id);setMatches(m);setLoading(false);
  },[tournament.id,user.id]);
  useEffect(()=>{setLoading(true);load();},[load]);

  const mUpd=k=>e=>setMForm(f=>({...f,[k]:e.target.value}));

  const handleAddMatch=async()=>{
    setMatchErr("");setAddingMatch(true);
    const r=await API.adminAddMatch(user.id,tournament.id,{...mForm,stage:mForm.stage||`Grupo ${mForm.group}`},token);
    setAddingMatch(false);
    if(r.error){setMatchErr(r.error);return;}
    showToast("Partido agregado");
    setMForm(f=>({...f,homeTeam:"",awayTeam:"",date:"",time:"18:00",stage:"",nextMatchWinnerId:"",nextMatchWinnerSlot:"home",nextMatchLoserId:"",nextMatchLoserSlot:"home"}));
    await load();
  };

  if(loading) return <div className="content"><div className="empty">Cargando...</div></div>;

  // Build stage nav from actual match data
  const GROUP_LABELS = {
    A:"Grupo A",B:"Grupo B",C:"Grupo C",D:"Grupo D",E:"Grupo E",F:"Grupo F",
    G:"Grupo G",H:"Grupo H",I:"Grupo I",J:"Grupo J",K:"Grupo K",L:"Grupo L",
    R32:"Ronda de 32",R16:"Octavos",QF:"Cuartos",SF:"Semis",
    "3P":"3er Puesto",FIN:"Final"
  };
  const STAGE_ORDER = ["A","B","C","D","E","F","G","H","I","J","K","L","R32","R16","QF","SF","3P","FIN"];
  const availableGroups = ["ALL", ...STAGE_ORDER.filter(g => matches.some(m=>m.group===g))];

  const groups = availableGroups;
  const filtered=group==="ALL"?matches:matches.filter(m=>m.group===group);
  const predCount=matches.filter(m=>m.myPrediction).length;

  return(
    <div className="content">
      <div className="t-hero">
        <div className="t-hero-banner">
          <div className="t-hero-logo">{tournament.logo}</div>
          <div>
            <div className="t-hero-name">{tournament.name}</div>
            <div className="t-hero-region">{tournament.region}</div>
            <div className="t-hero-dates">📅 {tournament.startDate} → {tournament.endDate}</div>
          </div>
        </div>
        <div className="t-hero-footer">
          <span className={"status-badge "+statusClass(tournament.status)}>{statusLabel(tournament.status)}</span>
          <span style={{fontSize:11,color:"var(--tx3)",fontFamily:"Barlow Condensed",letterSpacing:1}}>{predCount}/{matches.length} pronósticos</span>
          <span className={"source-chip "+(tournament.source==="fifa_api"?"src-fifa":"src-manual")} style={{marginLeft:"auto"}}>{tournament.source==="fifa_api"?"🌐 FIFA API":"✏ Manual"}</span>
        </div>
      </div>
      {isAdmin&&(
        <div className="admin-panel">
          <div className="ap-hdr">
            <div className="ap-title"><span style={{background:"rgba(255,68,68,.2)",padding:"1px 7px",borderRadius:8,fontSize:9,letterSpacing:2}}>ADMIN</span> Gestión del torneo</div>
          </div>
          <div className="ap-body">
            <div className="ap-tabs">
              <button className={"ap-tab"+(apTab==="status"?" active":"")} onClick={()=>setApTab("status")}>Estado</button>
              <button className={"ap-tab"+(apTab==="addMatch"?" active":"")} onClick={()=>setApTab("addMatch")}>+ Partido</button>
            </div>
            {apTab==="status"&&(
              <div className="ap-form">
                <div style={{display:"flex",flexDirection:"column"}}>
                  <label className="ap-label">Estado</label>
                  <select className="ap-select" value={editStatus} onChange={e=>setEditStatus(e.target.value)}>
                    <option value="upcoming">🟡 Próximo</option><option value="active">🟢 En curso</option><option value="finished">⚫ Finalizado</option>
                  </select>
                </div>
                <button className="btn btn-red" style={{alignSelf:"flex-end"}} onClick={async()=>{setSavingStatus(true);const r=await API.adminUpdateTournament(user.id,tournament.id,{status:editStatus},token);setSavingStatus(false);if(r.success)showToast("Estado actualizado");else showToast(r.error,"err");}} disabled={savingStatus}>
                  {savingStatus?"...":"ACTUALIZAR"}
                </button>
              </div>
            )}
            {apTab==="addMatch"&&(
              <>
                {matchErr&&<div className="msg-err" style={{marginBottom:10}}>{matchErr}</div>}
                <div className="mfg">
                  <div className="afield"><label className="ap-label">Local *</label><input className="ap-input" style={{width:"100%"}} value={mForm.homeTeam} onChange={mUpd("homeTeam")} placeholder="ej: Brasil 🇧🇷 o TBD:Ganador SF-1"/></div>
                  <div className="afield"><label className="ap-label">Visitante *</label><input className="ap-input" style={{width:"100%"}} value={mForm.awayTeam} onChange={mUpd("awayTeam")} placeholder="ej: Argentina 🇦🇷 o TBD:Ganador SF-2"/></div>
                  <div className="afield"><label className="ap-label">Grupo / Fase</label>
                    <select className="ap-select" style={{width:"100%"}} value={mForm.group} onChange={mUpd("group")}>
                      {(tournament.groups||["A","B","C","D"]).map(g=><option key={g} value={g}>{GROUP_LABELS?.[g]||"Grupo "+g}</option>)}
                    </select>
                  </div>
                  <div className="afield"><label className="ap-label">Nombre de etapa</label><input className="ap-input" style={{width:"100%"}} value={mForm.stage} onChange={mUpd("stage")} placeholder="ej: Semifinal"/></div>
                  <div className="afield"><label className="ap-label">Fecha</label><input className="ap-input" type="date" style={{width:"100%"}} value={mForm.date} onChange={mUpd("date")}/></div>
                  <div className="afield"><label className="ap-label">Hora</label><input className="ap-input" type="time" style={{width:"100%"}} value={mForm.time} onChange={mUpd("time")}/></div>
                </div>

                {/* Propagation fields — shown when any team has TBD or manually expanded */}
                <details style={{marginTop:8,marginBottom:10}}>
                  <summary style={{fontSize:10,letterSpacing:2,textTransform:"uppercase",color:"var(--gold)",fontFamily:"Barlow Condensed",cursor:"pointer",userSelect:"none"}}>
                    ⚙ Propagación de resultados (fase eliminatoria)
                  </summary>
                  <div style={{marginTop:10,padding:12,background:"rgba(201,168,76,.05)",border:"1px solid rgba(201,168,76,.15)",borderRadius:2}}>
                    <div style={{fontSize:10,color:"var(--tx3)",fontFamily:"Barlow Condensed",letterSpacing:1,marginBottom:10,lineHeight:1.6}}>
                      Configurá a qué partido siguiente avanza el ganador (y el perdedor, si aplica). Usá los IDs de los partidos ya creados.
                    </div>
                    <div className="mfg" style={{marginBottom:0}}>
                      <div className="afield">
                        <label className="ap-label">ID partido siguiente (ganador)</label>
                        <input className="ap-input" style={{width:"100%"}} value={mForm.nextMatchWinnerId} onChange={mUpd("nextMatchWinnerId")} placeholder="ej: m_1234567890"/>
                      </div>
                      <div className="afield">
                        <label className="ap-label">Posición del ganador</label>
                        <select className="ap-select" style={{width:"100%"}} value={mForm.nextMatchWinnerSlot} onChange={mUpd("nextMatchWinnerSlot")}>
                          <option value="home">🏠 Local</option>
                          <option value="away">✈ Visitante</option>
                        </select>
                      </div>
                      <div className="afield">
                        <label className="ap-label">ID partido siguiente (perdedor)</label>
                        <input className="ap-input" style={{width:"100%"}} value={mForm.nextMatchLoserId} onChange={mUpd("nextMatchLoserId")} placeholder="ej: m_1234567891 (tercer puesto)"/>
                      </div>
                      <div className="afield">
                        <label className="ap-label">Posición del perdedor</label>
                        <select className="ap-select" style={{width:"100%"}} value={mForm.nextMatchLoserSlot} onChange={mUpd("nextMatchLoserSlot")}>
                          <option value="home">🏠 Local</option>
                          <option value="away">✈ Visitante</option>
                        </select>
                      </div>
                    </div>
                  </div>
                </details>

                <button className="btn btn-red" onClick={handleAddMatch} disabled={addingMatch}>{addingMatch?"AGREGANDO...":"+ AGREGAR PARTIDO"}</button>
              </>
            )}
          </div>
        </div>
      )}
      <div style={{marginTop:20}}>
        <div className="groups-nav">
          {groups.map(g=>(
            <button key={g} className={"group-btn"+(group===g?" active":"")} onClick={()=>setGroup(g)}>
              {g==="ALL"?"Todos":(GROUP_LABELS[g]||"Grupo "+g)}
            </button>
          ))}
        </div>
        <div className="matches-list">
          {filtered.length===0?(
            <div className="empty">{isAdmin?"Sin partidos. Agregá uno.":"Sin partidos disponibles."}</div>
          ):filtered.map(m=>(
            <MatchCard key={m.id} match={m} tId={tournament.id} userId={user.id} token={token} isAdmin={isAdmin}
              onSave={async(mid,h,a)=>{const r=await API.savePrediction(user.id,tournament.id,mid,h,a);if(r.success){showToast("Pronóstico guardado");await load();}else showToast(r.error,"err");return r;}}
              onAdminSave={async(mid,h,a)=>{const r=await API.adminUpdateMatch(user.id,tournament.id,mid,h,a,token);if(r.success){showToast("Resultado guardado");await load();onPointsUpdate&&onPointsUpdate();}else showToast(r.error,"err");}}/>
          ))}
        </div>
      </div>
    </div>
  );
}

// ============================================================
// LEADERBOARD
// ============================================================
function LeaderboardView({activeTournament}){
  const [tournaments,setTournaments]=useState([]);
  const [selId,setSelId]=useState(activeTournament?.id||null);
  const [leaders,setLeaders]=useState([]);
  const [loading,setLoading]=useState(true);
  useEffect(()=>{API.getTournaments().then(l=>{setTournaments(l);if(!selId&&l.length)setSelId(l[0].id);});},[]);
  useEffect(()=>{if(!selId)return;setLoading(true);API.getLeaderboard(selId).then(l=>{setLeaders(l);setLoading(false);});},[selId]);
  const rc=i=>i===0?"g":i===1?"s":i===2?"b":"";
  const selT=tournaments.find(t=>t.id===selId);
  return(
    <div className="content">
      <div className="sec-title">CLASIFICACIÓN</div>
      <div className="sec-sub"><span className="db-dot"></span>Puntos por torneo</div>
      {tournaments.length>1&&(
        <div className="groups-nav" style={{marginBottom:18}}>
          {tournaments.map(t=><button key={t.id} className={"group-btn"+(selId===t.id?" active":"")} onClick={()=>setSelId(t.id)}>{t.logo} {t.shortName||t.name}</button>)}
        </div>
      )}
      {selT&&<div style={{marginBottom:14,display:"flex",alignItems:"center",gap:10}}>
        <span style={{fontSize:24}}>{selT.logo}</span>
        <div><div style={{fontFamily:"Bebas Neue",fontSize:17,letterSpacing:3}}>{selT.name}</div>
          <span className={"status-badge "+statusClass(selT.status)} style={{marginTop:3,display:"inline-block"}}>{statusLabel(selT.status)}</span>
        </div>
      </div>}
      {loading?<div className="empty">Cargando...</div>:(
        <>
          <div className="lb">
            <div className="lb-row hdr"><div>#</div><div>Jugador</div><div style={{textAlign:"right"}}>Pts</div><div style={{textAlign:"center"}}>Pred</div><div style={{textAlign:"center"}}>Exactos</div></div>
            {leaders.length===0?<div className="empty">Sin predicciones aún</div>:
              leaders.map((u,i)=>(
                <div key={u.id} className="lb-row">
                  <div className={"rank "+rc(i)}>{i+1}</div>
                  <div className="lb-user"><div className="lb-av">{u.avatar}</div><span style={{fontSize:13,fontWeight:500}}>{u.username}</span></div>
                  <div className="lb-pts">{u.points}</div>
                  <div className="lb-n">{u.predictions}</div>
                  <div className="lb-n" style={{color:"var(--gold)"}}>{u.exact}</div>
                </div>
              ))
            }
          </div>
          <div className="pts-info">
            <strong style={{color:"var(--tx2)"}}>Puntos:</strong>&nbsp;🥇 Exacto=<span style={{color:"var(--gold)"}}>3pts</span>&nbsp;|&nbsp;🥈 Resultado=<span style={{color:"var(--gold)"}}>1pt</span>&nbsp;|&nbsp;❌=<span style={{color:"var(--red)"}}>0pts</span>
          </div>
        </>
      )}
    </div>
  );
}


// ============================================================
// MAIN APP
// ============================================================
export default function App(){
  const [ready,setReady]       = useState(false);
  const [token,setToken]       = useState(null);
  const [user,setUser]         = useState(null);
  const [tab,setTab]           = useState("lobby");
  const [registering,setReg]   = useState(false); // show RegisterWithCodeScreen
  const [activeTournament,setActiveTournament] = useState(null);
  const [toast,setToast]       = useState(null);
  const [tk,setTk]             = useState(0);
  const [pendingInvCount,setPendingInvCount] = useState(0);

  useEffect(()=>{ Store.init().then(()=>setReady(true)); },[]);

  const showToast=useCallback((msg,type="ok")=>{ setToast({msg,type}); setTk(k=>k+1); },[]);
  const handleLogin=(t,u)=>{ setToken(t); setUser(u); setReg(false); };
  const handleLogout=()=>{ setToken(null); setUser(null); setTab("lobby"); setActiveTournament(null); setPendingInvCount(0); };

  const refreshPts=useCallback(async()=>{
    if(!user||!activeTournament) return;
    const pts=await API.getUserPoints(user.id,activeTournament.id);
    setUser(p=>({...p,tournamentPoints:pts}));
  },[user,activeTournament]);

  // Poll pending invitations count for admin badge
  useEffect(()=>{
    if(!user||user.role!=="admin") return;
    const check=async()=>{
      const r=await API.getInvitations(user.id,token);
      if(r.invitations) setPendingInvCount(r.invitations.filter(i=>i.status==="registered").length);
    };
    check();
    const interval=setInterval(check,30000);
    return ()=>clearInterval(interval);
  },[user,token]);

  const isAdmin=user?.role==="admin";

  const tabs=[
    {id:"lobby",        label:"Torneos"},
    {id:"matches",      label:"Partidos",      dis:!activeTournament},
    {id:"leaderboard",  label:"Clasificación"},
    {id:"invitations",  label:"Invitaciones"},  // visible to all logged-in users
    ...(isAdmin?[{id:"users",label:"Usuarios"}]:[]),
  ];

  if(!ready) return (<><style>{S}</style><div className="app"><Loader text="INICIANDO SUPER CAMPEONES..."/></div></>);

  return(
    <>
      <style>{S}</style>
      <div className="app">
        {!user ? (
          registering
            ? <RegisterWithCodeScreen onBack={()=>setReg(false)}/>
            : <LoginScreen onLogin={handleLogin} onRegister={()=>setReg(true)}/>
        ):(
          <>
            <nav className="navbar">
              <div className="nav-brand">🏆 SUPER CAMPEONES</div>
              <div className="nav-tabs">
                {tabs.map(t=>(
                  <button key={t.id} className={"nav-tab"+(tab===t.id?" active":"")}
                    style={t.dis?{opacity:.35,cursor:"not-allowed"}:{}}
                    onClick={()=>!t.dis&&setTab(t.id)}>
                    {t.label}
                    {t.id==="matches"&&activeTournament&&(
                      <span style={{marginLeft:5,fontSize:9,color:"var(--gold)",fontFamily:"Barlow Condensed"}}>{activeTournament.logo}</span>
                    )}
                    {t.id==="users"&&isAdmin&&pendingInvCount>0&&<span className="notif-dot"/>}
                  </button>
                ))}
              </div>
              <div className="nav-right">
                <div className="user-badge">
                  <span>{user.avatar}</span>
                  <span style={{fontSize:12}}>{user.username}</span>
                  {isAdmin&&<span className="admin-chip">admin</span>}
                  {activeTournament&&user.tournamentPoints!==undefined&&<span className="pts-chip">{user.tournamentPoints}pts</span>}
                </div>
                <button className="btn btn-ghost" style={{padding:"4px 10px",fontSize:11}} onClick={handleLogout}>Salir</button>
              </div>
            </nav>

            {tab==="lobby"&&(
              <TournamentLobby user={user} token={token} showToast={showToast}
                onSelect={t=>{setActiveTournament(t);setTab("matches");}}/>
            )}
            {tab==="matches"&&activeTournament&&(
              <MatchesView tournament={activeTournament} user={user} token={token}
                showToast={showToast} onPointsUpdate={refreshPts}/>
            )}
            {tab==="leaderboard"&&<LeaderboardView activeTournament={activeTournament}/>}
            {tab==="invitations"&&(
              <div className="content">
                <div className="sec-title">INVITACIONES</div>
                <div className="sec-sub">
                  <span className="db-dot"></span>
                  {isAdmin?"Gestioná y aprobá invitaciones de todos los usuarios":"Invitá amigos para participar en torneos"}
                </div>
                <InvitationsView user={user} token={token} showToast={showToast}
                  tournaments={[]} /* loaded inside */
                  key="inv-main"/>
              </div>
            )}
            {tab==="users"&&isAdmin&&(
              <UsersView user={user} token={token} showToast={showToast}/>
            )}
          </>
        )}
        {toast&&<Toast key={tk} message={toast.msg} type={toast.type} onClose={()=>setToast(null)}/>}
      </div>
    </>
  );
}