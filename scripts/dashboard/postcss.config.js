export default {
  plugins: {
    // tailwind 4 moved the PostCSS plugin to its own package, and does its own
    // vendor prefixing through Lightning CSS -- autoprefixer is no longer part
    // of the pipeline. See #390.
    '@tailwindcss/postcss': {},
  },
}
