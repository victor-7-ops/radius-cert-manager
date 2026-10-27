/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: "class",
  content: ["./app/templates/**/*.html"],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
      },
      colors: {
        // Neutral, low-chroma base. Color reserved for meaning, never
        // decoration — see app/templates/base.html for the badge map.
      },
    },
  },
  plugins: [],
};
