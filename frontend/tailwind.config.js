/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: [
          '"JetBrains Mono"',
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "monospace",
        ],
      },
      keyframes: {
        flashIn: {
          "0%": { backgroundColor: "rgba(16, 185, 129, 0.14)" },
          "100%": { backgroundColor: "rgba(15, 23, 42, 0)" },
        },
      },
      animation: {
        flashIn: "flashIn 1.6s ease-out",
      },
    },
  },
  plugins: [],
};
