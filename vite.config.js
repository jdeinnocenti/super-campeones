import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { VitePWA } from 'vite-plugin-pwa'
export default defineConfig({plugins:[react(),VitePWA({registerType:'autoUpdate',manifest:{name:'Super Campeones',short_name:'SC',description:'Pronosticá torneos de fútbol y competí con amigos',start_url:'/',display:'standalone',background_color:'#080c14',theme_color:'#c9a84c',icons:[{src:'/icons/icon-192.png',sizes:'192x192',type:'image/png',purpose:'any'},{src:'/icons/icon-512.png',sizes:'512x512',type:'image/png',purpose:'maskable'}]}})]})
