# 🚀 APK Security Intelligence Platform

> "Because poking around in Android apps shouldn't require a Ph.D. in reverse engineering." 🛠️👾

Hey there! 👋 Welcome to my weekend-project-turned-serious-tool. I love tinkering with Android apps, pulling them apart, and seeing how they tick. But manually checking manifests, digging for hardcoded API keys, and spotting Firebase misconfigurations gets tedious fast. 

So, I built this **APK Security Intelligence Platform** to automate the boring stuff and let AI summarize the spicy findings. 

Whether you're a bug bounty hunter, an Android dev wanting to check your own work, or just someone who likes to take things apart—this tool is for you. Built with a solid FastAPI backend and a slick, cyberpunk-inspired React frontend, it's designed to be powerful, modular, and—above all—fun to use.

---

## ✨ Features (The Cool Stuff)

- **Automated Unpacking:** Drops your APK into `apktool` and rips it open cleanly.
- **Deep Scanning Modules:**
  - 📜 **Manifest Analyzer:** Spots exported components, debuggable flags, and insecure configurations.
  - 🔐 **Permission Analyzer:** Flags dangerous and over-privileged permissions.
  - 🔑 **Secret Scanner:** Hunts down hardcoded API keys, passwords, and tokens.
  - 🔥 **Firebase Checker:** Detects open/misconfigured Firebase databases.
  - 🛡️ **SSL Checker:** Finds weak SSL/TLS implementations and broken trust managers.
  - 💾 **Storage Analyzer:** Spots insecure data storage practices.
- **🧠 AI-Powered Insights:** Hooks into **Groq** to generate an automated risk summary and remediation plan.
- **💬 Interactive Chat:** Got a question about a vulnerability? Just chat with the AI right inside the dashboard!
- **⚡ Fast & Asynchronous:** Runs scans in the background while feeding you live progress on the slick React frontend.

---

## 🏗️ Architecture

I like keeping things tidy. Here's how the stack breaks down:

### Backend (`/backend`)
- **Framework:** `FastAPI` (because speed matters).
- **Core Engine:** Custom modular design. Each scanner is a separate module, meaning you can easily add your own.
- **AI Integration:** Uses `groq` to parse findings and give human-readable feedback.

### Frontend (`/frontend`)
- **Framework:** `React 18` + `Vite` for lightning-fast HMR.
- **Styling:** Custom CSS. Clean, dark-mode, cyberpunk vibes. 

---

## 🚀 Getting Started

Want to spin this up on your local machine? Easy. 

### 1. Clone the repo
```bash
git clone https://github.com/your-username/apk-security-platform.git
cd apk-security-platform
```

### 2. Setup the Backend
You'll need `apktool` installed on your system for the unpacking magic to work.
```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
**Don't forget your `.env`!** Create one in the `backend/` directory:
```env
GROQ_API_KEY=your_groq_api_key_here
```
Run it:
```bash
uvicorn main:app --reload --port 8000
```

### 3. Setup the Frontend
```bash
cd ../frontend
npm install
npm run dev
```
Boom. 💥 Point your browser to `http://localhost:5173` and start analyzing.

---

## 🤝 Contributing

I built this because I love building cool tools, but it's totally open for improvements! If you want to add a new scanning module, tweak the UI, or fix a bug:
1. Fork it.
2. Create a feature branch (`git checkout -b feature/new-scanner`).
3. Commit your changes (keep your commit messages clean, standard git etiquette, please! 🧑‍💻).
4. Push to the branch (`git push origin feature/new-scanner`).
5. Open a Pull Request.

---

## 📜 License

MIT License. Do whatever you want with it, just don't use it for evil. 

---
*Happy hacking! Let's find some bugs.* 🐛
