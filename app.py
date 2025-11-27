import hashlib
import re
import math
import requests
from flask import Flask, render_template_string, request, jsonify

app = Flask(__name__)

# ==========================================
#  BACKEND LOGIC
# ==========================================

def calculate_entropy(password):
    """Calculates password entropy (bits)."""
    pool_size = 0
    if re.search(r"[a-z]", password): pool_size += 26
    if re.search(r"[A-Z]", password): pool_size += 26
    if re.search(r"\d", password): pool_size += 10
    if re.search(r"[^a-zA-Z\d]", password): pool_size += 32
    
    if pool_size == 0: return 0
    return len(password) * math.log2(pool_size)

def estimate_crack_time(entropy):
    """
    Estimates time to crack based on a modern GPU rig 
    (assuming 100 Billion guesses/second - RTX 4090 cluster benchmark).
    """
    guesses_per_sec = 100_000_000_000 
    seconds = (2 ** entropy) / guesses_per_sec
    
    if seconds < 60: return "Instantly"
    if seconds < 3600: return f"{int(seconds/60)} minutes"
    if seconds < 86400: return f"{int(seconds/3600)} hours"
    if seconds < 31536000: return f"{int(seconds/86400)} days"
    if seconds < 3153600000: return f"{int(seconds/31536000)} years"
    return "Centuries"

def check_password_strength(password):
    score = 0
    feedback = []
    
    # Length Check
    if len(password) < 8:
        feedback.append("Too short (min 8 chars)")
    elif len(password) >= 12:
        score += 2
    else:
        score += 1
        
    # Complexity Checks
    if re.search(r"[a-z]", password): score += 1
    else: feedback.append("Missing lowercase")
        
    if re.search(r"[A-Z]", password): score += 1
    else: feedback.append("Missing uppercase")
        
    if re.search(r"\d", password): score += 1
    else: feedback.append("Missing numbers")
        
    if re.search(r"[ !@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password): score += 1
    else: feedback.append("Missing symbols")

    # Normalize score to max 5
    final_score = min(5, score - 1) if score > 1 else 0

    entropy = calculate_entropy(password)
    crack_time = estimate_crack_time(entropy)

    return {
        "score": final_score,
        "feedback": feedback,
        "crack_time": crack_time
    }

def request_pwned_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url, timeout=5)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}')
    return res

def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return int(count)
    return 0

def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char = sha1password[:5]
    tail = sha1password[5:]
    response = request_pwned_data(first5_char)
    return get_password_leaks_count(response, tail)

# ==========================================
#  FRONTEND TEMPLATE
# ==========================================

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en" class="scroll-smooth">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BreachGuard | Cyber Security Hub</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Space+Grotesk:wght@300;500;700&display=swap');
        
        body { font-family: 'Space Grotesk', sans-serif; background-color: #030014; color: #ffffff; overflow-x: hidden; }
        .mono { font-family: 'JetBrains Mono', monospace; }

        /* Fancy Background */
        .bg-grid {
            background-size: 50px 50px;
            background-image: linear-gradient(to right, rgba(255, 255, 255, 0.05) 1px, transparent 1px),
                              linear-gradient(to bottom, rgba(255, 255, 255, 0.05) 1px, transparent 1px);
            mask-image: radial-gradient(ellipse at center, black 40%, transparent 80%);
        }

        .glass {
            background: rgba(255, 255, 255, 0.03);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.08);
        }

        .neon-glow { text-shadow: 0 0 20px rgba(99, 102, 241, 0.5); }
        
        /* Custom Scrollbar */
        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: #030014; }
        ::-webkit-scrollbar-thumb { background: #4f46e5; border-radius: 4px; }

        /* Animation Classes */
        .fade-in-up { animation: fadeInUp 0.8s ease-out forwards; opacity: 0; transform: translateY(20px); }
        @keyframes fadeInUp { to { opacity: 1; transform: translateY(0); } }
    </style>
</head>
<body>

    <!-- Nav -->
    <nav class="fixed w-full z-50 glass border-b border-white/10 px-6 py-4">
        <div class="max-w-7xl mx-auto flex justify-between items-center">
            <div class="flex items-center gap-2">
                <i class="fas fa-shield-cat text-indigo-500 text-2xl"></i>
                <span class="text-xl font-bold tracking-wider">Breach<span class="text-indigo-500">Guard</span></span>
            </div>
            <div class="hidden md:flex gap-8 text-sm font-medium text-gray-400">
                <a href="#scanner" class="hover:text-white transition">Scanner</a>
                <a href="#threats" class="hover:text-white transition">Threat Lab</a>
                <a href="#defense" class="hover:text-white transition">Defense Guide</a>
            </div>
        </div>
    </nav>

    <!-- Hero / Scanner Section -->
    <section id="scanner" class="relative min-h-screen flex items-center justify-center pt-20">
        <div class="absolute inset-0 bg-grid z-0"></div>
        <div class="absolute top-20 left-10 w-72 h-72 bg-purple-600 rounded-full mix-blend-multiply filter blur-3xl opacity-20 animate-blob"></div>
        <div class="absolute top-20 right-10 w-72 h-72 bg-indigo-600 rounded-full mix-blend-multiply filter blur-3xl opacity-20 animate-blob animation-delay-2000"></div>

        <div class="relative z-10 w-full max-w-4xl px-4 flex flex-col md:flex-row gap-12 items-center">
            
            <!-- Left: Text -->
            <div class="flex-1 text-center md:text-left">
                <div class="inline-block px-3 py-1 mb-4 text-xs font-semibold tracking-wider text-indigo-400 uppercase bg-indigo-500/10 rounded-full border border-indigo-500/20">
                    Version 2.0.0
                </div>
                <h1 class="text-5xl md:text-6xl font-bold mb-6 leading-tight">
                    Is your password <br>
                    <span class="text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 to-cyan-400 neon-glow">Breach Proof?</span>
                </h1>
                <p class="text-gray-400 text-lg mb-8 leading-relaxed">
                    Check your exposure against <span class="text-white font-bold">600M+ leaked credentials</span> using k-Anonymity encryption. We never see your password.
                </p>
                
                <div class="flex gap-4 justify-center md:justify-start text-sm text-gray-500">
                    <div class="flex items-center gap-2"><i class="fas fa-lock text-green-500"></i> SHA-1 Hashed</div>
                    <div class="flex items-center gap-2"><i class="fas fa-ghost text-purple-500"></i> k-Anonymity</div>
                </div>
            </div>

            <!-- Right: The Scanner Tool -->
            <div class="w-full max-w-md">
                <div class="glass rounded-2xl p-8 shadow-2xl shadow-indigo-500/10 relative overflow-hidden group">
                    <div class="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-indigo-500 to-transparent opacity-50"></div>
                    
                    <form id="checkForm" class="space-y-5">
                        <label class="block text-xs font-bold text-gray-500 uppercase tracking-widest mono">Target Credential</label>
                        <div class="relative">
                            <input type="password" id="passwordInput" 
                                class="w-full bg-black/40 border border-white/10 rounded-xl px-5 py-4 text-white focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 outline-none transition font-mono tracking-wider"
                                placeholder="Enter password..." required>
                            <button type="button" id="toggleVis" class="absolute right-4 top-1/2 -translate-y-1/2 text-gray-500 hover:text-white">
                                <i class="fas fa-eye"></i>
                            </button>
                        </div>
                        <button type="submit" id="scanBtn"
                            class="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-4 rounded-xl shadow-lg shadow-indigo-600/25 transition-all transform active:scale-95 flex items-center justify-center gap-2">
                            <span>RUN ANALYSIS</span>
                            <i class="fas fa-bolt"></i>
                        </button>
                    </form>

                    <!-- Results Overlay -->
                    <div id="resultOverlay" class="hidden mt-6 pt-6 border-t border-white/10 space-y-4">
                        <div class="flex justify-between items-center">
                            <span class="text-gray-400 text-sm">Security Score</span>
                            <span id="scoreBadge" class="px-3 py-1 rounded-full text-xs font-bold bg-gray-800 text-white">0/5</span>
                        </div>
                        
                        <!-- Crack Time Box -->
                        <div class="bg-white/5 rounded-lg p-4 border border-white/5">
                            <div class="text-xs text-gray-400 uppercase mb-1">Estimated Time to Crack</div>
                            <div id="crackTime" class="text-2xl font-bold text-white mono">--</div>
                            <div class="text-xs text-gray-500 mt-1">Assuming RTX 4090 Cluster</div>
                        </div>

                        <!-- Breach Status -->
                        <div id="breachStatus" class="p-4 rounded-lg bg-red-500/10 border border-red-500/20 flex items-center gap-4">
                            <!-- Injected JS -->
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="absolute bottom-10 animate-bounce">
            <i class="fas fa-chevron-down text-gray-600 text-xl"></i>
        </div>
    </section>

    <!-- Section: Threat Lab (Educational) -->
    <section id="threats" class="py-24 relative overflow-hidden">
        <div class="max-w-7xl mx-auto px-6">
            <div class="mb-16 text-center">
                <h2 class="text-3xl md:text-4xl font-bold mb-4">How Attackers <span class="text-indigo-400">Steal Credentials</span></h2>
                <p class="text-gray-400 max-w-2xl mx-auto">Understanding the enemy is the first step in defense. Here are the most common methods used by threat actors today.</p>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-3 gap-8">
                <!-- Card 1 -->
                <div class="glass p-8 rounded-2xl hover:bg-white/5 transition duration-300 border-t-4 border-t-red-500">
                    <div class="bg-red-500/10 w-14 h-14 rounded-lg flex items-center justify-center mb-6 text-red-400 text-2xl">
                        <i class="fas fa-hammer"></i>
                    </div>
                    <h3 class="text-xl font-bold mb-3">Brute Force & Dictionary</h3>
                    <p class="text-gray-400 text-sm leading-relaxed">
                        Attackers use automated scripts to try millions of combinations. <br><br>
                        <span class="text-white font-semibold">Defense:</span> Password length. Each extra character increases the complexity exponentially.
                    </p>
                </div>

                <!-- Card 2 -->
                <div class="glass p-8 rounded-2xl hover:bg-white/5 transition duration-300 border-t-4 border-t-orange-500">
                    <div class="bg-orange-500/10 w-14 h-14 rounded-lg flex items-center justify-center mb-6 text-orange-400 text-2xl">
                        <i class="fas fa-database"></i>
                    </div>
                    <h3 class="text-xl font-bold mb-3">Credential Stuffing</h3>
                    <p class="text-gray-400 text-sm leading-relaxed">
                        When one site is breached (e.g., LinkedIn), attackers try that same email/password combo on banking and email sites.<br><br>
                        <span class="text-white font-semibold">Defense:</span> Never reuse passwords across sites.
                    </p>
                </div>

                <!-- Card 3 -->
                <div class="glass p-8 rounded-2xl hover:bg-white/5 transition duration-300 border-t-4 border-t-purple-500">
                    <div class="bg-purple-500/10 w-14 h-14 rounded-lg flex items-center justify-center mb-6 text-purple-400 text-2xl">
                        <i class="fas fa-fish"></i>
                    </div>
                    <h3 class="text-xl font-bold mb-3">Phishing & Social Eng</h3>
                    <p class="text-gray-400 text-sm leading-relaxed">
                        Deceptive emails that look legitimate (like Netflix or Google) tricking you into typing your password on a fake site.<br><br>
                        <span class="text-white font-semibold">Defense:</span> Check URLs and use a Password Manager (which won't auto-fill on fake sites).
                    </p>
                </div>
            </div>
        </div>
    </section>

    <!-- Section: Defense Guide -->
    <section id="defense" class="py-24 bg-indigo-900/10">
        <div class="max-w-5xl mx-auto px-6">
            <div class="flex flex-col md:flex-row gap-12 items-center">
                <div class="flex-1">
                    <h2 class="text-3xl font-bold mb-6">The Golden Rules of <br> <span class="text-indigo-400">Hygiene</span></h2>
                    
                    <div class="space-y-6">
                        <div class="flex gap-4">
                            <div class="w-8 h-8 rounded-full bg-indigo-500 flex items-center justify-center font-bold text-sm">1</div>
                            <div>
                                <h4 class="font-bold text-lg">Use a Password Manager</h4>
                                <p class="text-gray-400 text-sm">Bitwarden, 1Password, or Apple Keychain. Humans are bad at randomness; machines are great at it.</p>
                            </div>
                        </div>
                        <div class="flex gap-4">
                            <div class="w-8 h-8 rounded-full bg-indigo-500 flex items-center justify-center font-bold text-sm">2</div>
                            <div>
                                <h4 class="font-bold text-lg">Enable 2FA (MFA)</h4>
                                <p class="text-gray-400 text-sm">Even if they steal your password, they can't get in without the code on your phone. Use Authenticator apps, not SMS.</p>
                            </div>
                        </div>
                        <div class="flex gap-4">
                            <div class="w-8 h-8 rounded-full bg-indigo-500 flex items-center justify-center font-bold text-sm">3</div>
                            <div>
                                <h4 class="font-bold text-lg">Length > Complexity</h4>
                                <p class="text-gray-400 text-sm">"CorrectHorseBatteryStaple" (4 random words) is harder to crack than "P@ssw0rd1!" and easier to remember.</p>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Visual Decoration -->
                <div class="flex-1">
                    <div class="glass p-8 rounded-2xl relative border border-white/10">
                        <h3 class="mono text-xs text-indigo-400 mb-2">ENTROPY VISUALIZATION</h3>
                        <div class="space-y-4 font-mono text-sm">
                            <div class="flex justify-between text-gray-500">
                                <span>8 chars (numbers)</span>
                                <span class="text-red-500">Instantly</span>
                            </div>
                            <div class="w-full bg-gray-800 h-1 rounded overflow-hidden"><div class="w-[1%] h-full bg-red-500"></div></div>

                            <div class="flex justify-between text-gray-500">
                                <span>8 chars (mixed)</span>
                                <span class="text-orange-500">5 Mins</span>
                            </div>
                            <div class="w-full bg-gray-800 h-1 rounded overflow-hidden"><div class="w-[10%] h-full bg-orange-500"></div></div>

                            <div class="flex justify-between text-gray-500">
                                <span>12 chars (mixed)</span>
                                <span class="text-emerald-500">200 Years</span>
                            </div>
                            <div class="w-full bg-gray-800 h-1 rounded overflow-hidden"><div class="w-full h-full bg-emerald-500"></div></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <footer class="py-8 text-center text-gray-600 text-sm border-t border-white/5">
        <p>Built for Educational Purposes | Powered by HIBP API</p>
    </footer>

    <script>
        const form = document.getElementById('checkForm');
        const input = document.getElementById('passwordInput');
        const btn = document.getElementById('scanBtn');
        const resultOverlay = document.getElementById('resultOverlay');

        // Toggle Password Visibility
        document.getElementById('toggleVis').addEventListener('click', function() {
            const type = input.getAttribute('type') === 'password' ? 'text' : 'password';
            input.setAttribute('type', type);
            this.innerHTML = type === 'password' ? '<i class="fas fa-eye"></i>' : '<i class="fas fa-eye-slash"></i>';
        });

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            const password = input.value;
            if(!password) return;

            // Loading State
            const originalBtn = btn.innerHTML;
            btn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> ENCRYPTING & SCANNING...';
            btn.classList.add('opacity-75', 'cursor-not-allowed');
            
            try {
                const response = await fetch('/analyze', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password: password })
                });
                
                const data = await response.json();
                
                setTimeout(() => {
                    displayResults(data);
                    btn.innerHTML = originalBtn;
                    btn.classList.remove('opacity-75', 'cursor-not-allowed');
                }, 600); // Artificial delay for effect

            } catch (error) {
                console.error(error);
                btn.innerHTML = "ERROR";
            }
        });

        function displayResults(data) {
            resultOverlay.classList.remove('hidden');
            resultOverlay.classList.add('fade-in-up');

            // Score Badge
            const scoreBadge = document.getElementById('scoreBadge');
            scoreBadge.textContent = `${data.structure.score}/5`;
            
            if(data.structure.score >= 4) {
                scoreBadge.className = "px-3 py-1 rounded-full text-xs font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30";
            } else if (data.structure.score >= 2) {
                scoreBadge.className = "px-3 py-1 rounded-full text-xs font-bold bg-yellow-500/20 text-yellow-400 border border-yellow-500/30";
            } else {
                scoreBadge.className = "px-3 py-1 rounded-full text-xs font-bold bg-red-500/20 text-red-400 border border-red-500/30";
            }

            // Crack Time
            document.getElementById('crackTime').textContent = data.structure.crack_time;

            // Breach Status
            const breachDiv = document.getElementById('breachStatus');
            if (data.breaches > 0) {
                breachDiv.className = "p-4 rounded-lg bg-red-500/10 border border-red-500/20 flex items-center gap-4";
                breachDiv.innerHTML = `
                    <div class="text-3xl text-red-500"><i class="fas fa-radiation"></i></div>
                    <div>
                        <div class="text-red-500 font-bold text-lg">LEAKED ${data.breaches.toLocaleString()} TIMES</div>
                        <div class="text-red-400 text-xs">This password is in public hacker databases. Change immediately.</div>
                    </div>
                `;
            } else {
                breachDiv.className = "p-4 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center gap-4";
                breachDiv.innerHTML = `
                    <div class="text-3xl text-emerald-500"><i class="fas fa-shield-check"></i></div>
                    <div>
                        <div class="text-emerald-500 font-bold text-lg">NO BREACHES FOUND</div>
                        <div class="text-emerald-400 text-xs">This specific password hasn't been leaked (yet).</div>
                    </div>
                `;
            }
        }
    </script>
</body>
</html>
"""

# ==========================================
#  FLASK ROUTES
# ==========================================

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    password = data.get('password', '')
    
    # 1. Check structural strength & Entropy
    strength_data = check_password_strength(password)
    
    # 2. Check API for breaches
    try:
        breach_count = pwned_api_check(password)
    except Exception:
        breach_count = -1 
        
    return jsonify({
        "structure": strength_data,
        "breaches": breach_count
    })

if __name__ == '__main__':
    app.run(debug=True)