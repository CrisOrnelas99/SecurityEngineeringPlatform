import { defineConfig } from "vite";

export default defineConfig({
  build: {
    minify: "esbuild",
    sourcemap: false,
    cssMinify: true,
    target: "es2019"
  },
  esbuild: {
    drop: ["debugger"]
  }
});
