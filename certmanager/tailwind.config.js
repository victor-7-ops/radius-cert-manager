/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./app/templates/**/*.html"],
  theme: {
    extend: {
      colors: {
        // Neutral, low-chroma base. Color reserved for meaning, never
        // decoration — see app/templates/base.html for the badge map.
      },
    },
  },
  plugins: [],
};
