import { defineConfig } from "vite";
import path from "node:path";

export default defineConfig({
  esbuild: {
    jsxInject: 'import React from "react"',
  },
  resolve: {
    alias: {
      "@remix-run/router": path.resolve(
        __dirname,
        "node_modules/@remix-run/router/dist/router.js",
      ),
      "firebase/firebase-app.js": path.resolve(
        __dirname,
        "node_modules/firebase/firebase-app.js",
      ),
      "firebase/firebase-auth.js": path.resolve(
        __dirname,
        "node_modules/firebase/firebase-auth.js",
      ),
    },
  },
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: process.env.VITE_PROXY_TARGET || "http://127.0.0.1:5000",
        changeOrigin: true,
      },
    },
  },
});
