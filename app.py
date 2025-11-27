import hashlib
import re
import requests
from flask import Flask, render_template_string, request, jsonify

app = Flask(__name__)

# ==========================================
#  BACKEND LOGIC
# ==========================================

def check_password_strength(password):
    """
    Analyzes password complexity and returns a score (0-5) and missing criteria.
    """
    score = 0
    feedback = []
    
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Too short (min 8 chars)")
        
    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Missing lowercase")
        
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Missing uppercase")
        
    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Missing numbers")
        
    if re.search(r"[ !@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
        score += 1
    else:
        feedback.append("Missing symbols")

    return {
        "score": score,
        "feedback": feedback,
        "valid": score >= 4 # Consider it "valid" structurally if it hits most checks
    }

def request_pwned_data(query_char):
    """Query the HIBP API with the first 5 chars of the hash."""
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check API connection')
    return res

def get_password_leaks_count(hashes, hash_to_check):
    """Check the returned hashes to see if ours is in there."""
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return int(count)
    return 0

def pwned_api_check(password):
    """
    Main function to check password against HIBP API.
    Uses k-anonymity model (only sends first 5 chars of SHA1 hash).
    """
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char = sha1password[:5]
    tail = sha1password[5:]
    
    response = request_pwned_data(first5_char)
    return get_password_leaks_count(response, tail)

# ==========================================
#  FRONTEND TEMPLATE (HTML/CSS/JS)
# ==========================================

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BreachGuard | Secure Password Analyzer</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;600;800&display=swap');
        
        body {
            font-family: 'Inter', sans-serif;
            background-color: #050505;
            color: #ffffff;
            overflow-x: hidden;
        }

        .mono { font-family: 'JetBrains Mono', monospace; }

        /* Animated Background Mesh */
        .gradient-bg {
            position: fixed;
            top: 0; left: 0; width: 100%; height: 100%;
            background: 
                radial-gradient(circle at 15% 50%, rgba(76, 29, 149, 0.15) 0%, transparent 25%), 
                radial-gradient(circle at 85% 30%, rgba(16, 185, 129, 0.1) 0%, transparent 25%);
            z-index: -1;
        }

        /* Glassmorphism Card */
        .glass-panel {
            background: rgba(255, 255, 255, 0.03);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid rgba(255, 255, 255, 0.08);
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
        }

        /* Custom Input Styling */
        .custom-input {
            background: rgba(0, 0, 0, 0.4);
            border: 1px solid #333;
            transition: all 0.3s ease;
        }
        .custom-input:focus {
            border-color: #6366f1;
            box-shadow: 0 0 0 4px rgba(99, 102, 241, 0.1);
            outline: none;
        }

        /* Scan Line Animation */
        .scan-line {
            width: 100%;
            height: 2px;
            background: #10b981;
            position: absolute;
            top: 0;
            left: 0;
            opacity: 0;
            box-shadow: 0 0 10px #10b981;
        }
        .scanning .scan-line {
            animation: scan 1.5s ease-in-out infinite;
            opacity: 1;
        }
        @keyframes scan {
            0% { top: 0%; opacity: 0; }
            10% { opacity: 1; }
            90% { opacity: 1; }
            100% { top: 100%; opacity: 0; }
        }

        /* Result Cards Animation */
        .result-enter {
            animation: slideUp 0.5s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        }
        @keyframes slideUp {
            from { transform: translateY(20px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }
    </style>
</head>
<body class="min-h-screen flex flex-col items-center justify-center p-4">

    <div class="gradient-bg"></div>

    <div class="max-w-xl w-full">
        <!-- Header -->
        <div class="text-center mb-10">
            <div class="inline-flex items-center justify-center p-3 bg-indigo-500/10 rounded-xl mb-4 border border-indigo-500/20">
                <i class="fas fa-shield-halved text-3xl text-indigo-400"></i>
            </div>
            <h1 class="text-4xl md:text-5xl font-extrabold tracking-tight mb-2">
                Breach<span class="text-indigo-500">Guard</span>
            </h1>
            <p class="text-gray-400">Deep scanning heuristic analysis & exposure verification.</p>
        </div>

        <!-- Main Input Card -->
        <div class="glass-panel rounded-2xl p-8 relative overflow-hidden" id="mainCard">
            <div class="scan-line"></div>
            
            <form id="checkForm" class="space-y-6">
                <div>
                    <label class="block text-sm font-medium text-gray-400 mb-2 mono">ENTER CREDENTIAL STRING</label>
                    <div class="relative">
                        <input type="password" id="passwordInput" 
                            class="custom-input w-full px-5 py-4 rounded-xl text-lg text-white placeholder-gray-600"
                            placeholder="Type password to analyze..." required>
                        <button type="button" id="toggleVisibility" class="absolute right-4 top-1/2 transform -translate-y-1/2 text-gray-500 hover:text-white transition">
                            <i class="fas fa-eye"></i>
                        </button>
                    </div>
                </div>

                <button type="submit" 
                    class="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-4 rounded-xl transition duration-200 shadow-lg shadow-indigo-600/20 flex items-center justify-center group">
                    <span id="btnText">INITIATE SCAN</span>
                    <i class="fas fa-arrow-right ml-2 transform group-hover:translate-x-1 transition"></i>
                </button>
            </form>
        </div>

        <!-- Results Container -->
        <div id="resultsArea" class="mt-8 hidden space-y-4">
            
            <!-- Analysis Grid -->
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <!-- Structure Score -->
                <div class="glass-panel p-6 rounded-xl result-enter" style="animation-delay: 0.1s">
                    <h3 class="text-gray-400 text-xs font-bold tracking-wider uppercase mb-2 mono">Structure Integrity</h3>
                    <div class="flex items-end items-center gap-3">
                        <span id="scoreVal" class="text-4xl font-bold">0</span>
                        <span class="text-gray-500 text-sm mb-2">/ 5</span>
                    </div>
                    <div class="w-full bg-gray-700 h-1.5 mt-4 rounded-full overflow-hidden">
                        <div id="scoreBar" class="h-full bg-red-500 w-0 transition-all duration-1000"></div>
                    </div>
                    <p id="complexityText" class="mt-3 text-sm text-gray-300"></p>
                </div>

                <!-- Breach Status -->
                <div class="glass-panel p-6 rounded-xl result-enter" style="animation-delay: 0.2s">
                    <h3 class="text-gray-400 text-xs font-bold tracking-wider uppercase mb-2 mono">Global Database Check</h3>
                    <div id="breachIconContainer" class="mt-1">
                        <!-- Icons injected via JS -->
                    </div>
                    <div id="breachTextContainer" class="mt-2">
                        <!-- Text injected via JS -->
                    </div>
                </div>
            </div>

            <!-- Feedback Message -->
            <div id="feedbackCard" class="glass-panel p-5 rounded-xl border-l-4 border-yellow-500 hidden result-enter" style="animation-delay: 0.3s">
                <h4 class="font-bold text-yellow-500 mb-1"><i class="fas fa-triangle-exclamation mr-2"></i>Improvements Needed</h4>
                <ul id="feedbackList" class="text-sm text-gray-300 list-disc list-inside"></ul>
            </div>

        </div>
    </div>

    <script>
        const form = document.getElementById('checkForm');
        const input = document.getElementById('passwordInput');
        const mainCard = document.getElementById('mainCard');
        const btnText = document.getElementById('btnText');
        const resultsArea = document.getElementById('resultsArea');
        
        // Visibility Toggle
        document.getElementById('toggleVisibility').addEventListener('click', function() {
            const type = input.getAttribute('type') === 'password' ? 'text' : 'password';
            input.setAttribute('type', type);
            this.innerHTML = type === 'password' ? '<i class="fas fa-eye"></i>' : '<i class="fas fa-eye-slash"></i>';
        });

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            const password = input.value;
            if(!password) return;

            // UI Loading State
            mainCard.classList.add('scanning');
            btnText.textContent = "SCANNING ENCRYPTED CHANNELS...";
            resultsArea.classList.add('hidden');
            
            try {
                const response = await fetch('/analyze', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password: password })
                });
                
                const data = await response.json();
                
                // Simulate a slight delay for the "cool scanner" effect
                setTimeout(() => {
                    displayResults(data);
                    mainCard.classList.remove('scanning');
                    btnText.textContent = "SCAN COMPLETE";
                    setTimeout(() => btnText.textContent = "INITIATE SCAN", 2000);
                }, 800);

            } catch (error) {
                console.error('Error:', error);
                mainCard.classList.remove('scanning');
                btnText.textContent = "SYSTEM ERROR";
            }
        });

        function displayResults(data) {
            resultsArea.classList.remove('hidden');

            // 1. Update Score
            const score = data.structure.score;
            document.getElementById('scoreVal').textContent = score;
            
            const bar = document.getElementById('scoreBar');
            bar.style.width = (score / 5 * 100) + '%';
            
            // Color Logic for Bar
            if(score <= 2) bar.className = "h-full bg-red-500 transition-all duration-1000";
            else if(score <= 4) bar.className = "h-full bg-yellow-400 transition-all duration-1000";
            else bar.className = "h-full bg-emerald-400 transition-all duration-1000";

            document.getElementById('complexityText').textContent = score === 5 ? "Excellent Complexity" : "Weak structure detected.";

            // 2. Update Breach Data
            const count = data.breaches;
            const breachContainer = document.getElementById('breachIconContainer');
            const textContainer = document.getElementById('breachTextContainer');

            if (count > 0) {
                breachContainer.innerHTML = '<i class="fas fa-radiation text-4xl text-red-500 animate-pulse"></i>';
                textContainer.innerHTML = `
                    <p class="text-2xl font-bold text-red-500">${count.toLocaleString()}</p>
                    <p class="text-sm text-red-400">Times found in leaks</p>
                `;
            } else {
                breachContainer.innerHTML = '<i class="fas fa-check-circle text-4xl text-emerald-500"></i>';
                textContainer.innerHTML = `
                    <p class="text-2xl font-bold text-emerald-500">Secure</p>
                    <p class="text-sm text-emerald-400">No breaches found</p>
                `;
            }

            // 3. Feedback
            const fbList = document.getElementById('feedbackList');
            const fbCard = document.getElementById('feedbackCard');
            
            fbList.innerHTML = '';
            if (data.structure.feedback.length > 0) {
                fbCard.classList.remove('hidden');
                data.structure.feedback.forEach(item => {
                    const li = document.createElement('li');
                    li.textContent = item;
                    fbList.appendChild(li);
                });
            } else {
                fbCard.classList.add('hidden');
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
    
    # 1. Check structural strength
    strength_data = check_password_strength(password)
    
    # 2. Check API for breaches
    # Note: We catch errors here to prevent the page from breaking if user has no internet
    try:
        breach_count = pwned_api_check(password)
    except Exception as e:
        breach_count = -1 # Indicates API error
        
    return jsonify({
        "structure": strength_data,
        "breaches": breach_count
    })

if __name__ == '__main__':
    print("Starting BreachGuard Server...")
    print("Open your browser and go to http://127.0.0.1:5000")
    app.run(debug=True)