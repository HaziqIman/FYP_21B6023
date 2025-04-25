document.addEventListener('DOMContentLoaded', function () {

  let userIsActive = false;

  function markActivity() {
    userIsActive = true;
  }

  ['mousemove', 'keydown', 'click'].forEach(evt => {
    document.addEventListener(evt, markActivity);
  });

  setInterval(() => {
    if (userIsActive) {
      fetch('/user-active', { method: 'POST' })
        .then(res => {
          if (res.status === 401) {
            window.location.href = '/login'; 
          }
        })
        .catch(console.error);
      userIsActive = false;
    }
  }, 300000);
  

  const categories = ["Abuse", "Ads", "Fraud", "Gambling", "Malware", "Phishing", "Piracy", "Porn", "Ransomware", "Scam", "Tracking"];
  const container = document.querySelector(".category-container");
  
  categories.forEach(category => {
      const categoryBox = document.createElement("div");
      categoryBox.classList.add("category-box");
  
      const textSpan = document.createElement("span");
      textSpan.classList.add("category-text");
      textSpan.textContent = category;
  
      const dropdown = document.createElement("select");
      dropdown.classList.add("category-select");
      dropdown.setAttribute("data-category", category.toLowerCase());
      dropdown.innerHTML = `
          <option value="allow">Allow</option>
          <option value="block">Block</option>
      `;
  
      categoryBox.appendChild(textSpan);
      categoryBox.appendChild(dropdown);
      container.appendChild(categoryBox);
  });
  
  document.getElementById("apply-rules").addEventListener("click", () => {
      const selectedCategories = {};
      document.querySelectorAll(".category-select").forEach(select => {
          selectedCategories[select.getAttribute("data-category")] = select.value;
      });
  
      fetch("/apply-rules", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(selectedCategories)
      })
      .then(response => response.json())
      .then(data => alert(data.message))
      .catch(error => console.error("Error:", error));
  });

  // DNS Filtering Toggle
  document.getElementById("enable-dns").addEventListener("click", () => {
    fetch("/toggle-dns", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "on" })
    })
    .then(response => response.json())
    .then(data => alert(data.message))
    .catch(error => console.error("Error:", error));
});

document.getElementById("disable-dns").addEventListener("click", () => {
    fetch("/toggle-dns", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "off" })
    })
    .then(response => response.json())
    .then(data => alert(data.message))
    .catch(error => console.error("Error:", error));
});


  document.getElementById('unblock-button').addEventListener('click', async function () {
    // Grab the URL from the same text box
    const urlToUnblock = document.getElementById('filter-url').value;
  
    // Make a POST request to /unblock-url/<the URL>
    const response = await fetch('/unblock-url/' + encodeURIComponent(urlToUnblock), {
      method: 'POST'
    });
  
    const data = await response.json();
    alert(data.message);
  });
  
  document.getElementById("filter-form").addEventListener("submit", async (event) => {
    event.preventDefault();  // Stop the normal form submission
    const formData = new FormData(event.target);
  
    const response = await fetch("/apply-filter", {
      method: "POST",
      body: formData
    });
    const result = await response.json();
  
    if (result.status === "success") {
      alert(result.message); // or show it on the page
    } else {
      alert("Error: " + result.message);
    }
  });

// --- 1) In‑memory arrays (persisted to localStorage) ---
  let inboundData  = [];
  let outboundData = [];
  let timestamps   = [];

  // --- 2) Filter window lengths (ms) ---
  const filterDurations = {
    minute: 60 * 1000,
    hour:   60 * 60 * 1000,
    day:    24 * 60 * 60 * 1000
  };

  // --- 3) Load from localStorage if present ---
  function loadSavedData() {
    const ts  = JSON.parse(localStorage.getItem('bw.timestamps') || 'null');
    const inb = JSON.parse(localStorage.getItem('bw.inbound')    || 'null');
    const out = JSON.parse(localStorage.getItem('bw.outbound')   || 'null');

    if (
      Array.isArray(ts) &&
      Array.isArray(inb) &&
      Array.isArray(out) &&
      ts.length === inb.length &&
      ts.length === out.length
    ) {
      timestamps   = ts.map(t => new Date(t));
      inboundData  = inb.slice();
      outboundData = out.slice();
    }
  }

  // --- 4) Save current arrays into localStorage ---
  function saveData() {
    localStorage.setItem('bw.timestamps', JSON.stringify(timestamps));
    localStorage.setItem('bw.inbound',    JSON.stringify(inboundData));
    localStorage.setItem('bw.outbound',   JSON.stringify(outboundData));
  }

  // --- 5) Update min/max/avg table cells ---
  function updateTableMetrics(type, dataArray) {
    if (!dataArray.length) return;
    const max = Math.max(...dataArray).toFixed(2);
    const min = Math.min(...dataArray).toFixed(2);
    const avg = (dataArray.reduce((a,b) => a + b, 0) / dataArray.length).toFixed(2);
    document.getElementById(type + 'Max').textContent = max;
    document.getElementById(type + 'Avg').textContent = avg;
    document.getElementById(type + 'Min').textContent = min;
  }

  // --- 6) Initialize Chart.js ---
  const ctx = document.getElementById('bandwidthChart').getContext('2d');
  const bandwidthChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        {
          label: 'Inbound Bandwidth (Mbps)',
          data: [],
          borderWidth: 2,
          borderColor: 'rgba(75, 192, 192, 1)',
          backgroundColor: 'rgba(75, 192, 192, 0.2)',
          tension: 0.4,
          pointRadius: 0,
          fill: true,
        },
        {
          label: 'Outbound Bandwidth (Mbps)',
          data: [],
          borderWidth: 2,
          borderColor: '#bf71ff',
          backgroundColor: 'rgba(248, 175, 251, 0.2)',
          tension: 0.4,
          pointRadius: 0,
          fill: true,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          title: { display: true, text: 'Time' },
          ticks: {
            autoSkip: true,
            maxTicksLimit: 10,
            callback: (value, index) => {
              const ts = timestamps[index];
              return ts
                ? ts.toLocaleTimeString('en-GB', {
                    hour:   '2-digit',
                    minute: '2-digit',
                    second: '2-digit',
                    hour12: false,
                  })
                : '';
            },
          },
        },
        y: {
          title: { display: true, text: 'Bandwidth (Mbps)' },
        },
      },
    },
  });

  // --- 7) Seed chart with any saved data ---
  loadSavedData();
  bandwidthChart.data.labels                = timestamps.map(ts => ts.toISOString());
  bandwidthChart.data.datasets[0].data      = inboundData;
  bandwidthChart.data.datasets[1].data      = outboundData;
  bandwidthChart.update();
  updateTableMetrics('inbound', inboundData);
  updateTableMetrics('outbound', outboundData);

  // --- 8) Fetch fresh data, update arrays/chart/table, persist ---
  function updateBandwidthChart() {
    fetch('/get-bandwidth-usage')
      .then(r => r.json())
      .then(data => {
        const now    = new Date();
        const filter = document.getElementById('timeFilter').value;
        const windowMs = filterDurations[filter] || filterDurations.hour;
        const cutoff   = new Date(now.getTime() - windowMs);

        timestamps.push(now);
        inboundData.push(data.instant.received);
        outboundData.push(data.instant.sent);

        // drop old points
        while (timestamps.length && timestamps[0] < cutoff) {
          timestamps.shift();
          inboundData.shift();
          outboundData.shift();
        }

        // re-draw
        bandwidthChart.data.labels           = timestamps.map(ts => ts.toISOString());
        bandwidthChart.data.datasets[0].data = inboundData;
        bandwidthChart.data.datasets[1].data = outboundData;
        bandwidthChart.update();

        updateTableMetrics('inbound', inboundData);
        updateTableMetrics('outbound', outboundData);

        saveData();
      })
      .catch(console.error);
  }

  // --- 9) Wire up filter dropdown & polling ---
  document.getElementById('timeFilter')
    .addEventListener('change', updateBandwidthChart);
  setInterval(updateBandwidthChart, 10_000);
  updateBandwidthChart();



  function createDonutChart(ctx, initialValue) {
    return new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Used', 'Free'],
            datasets: [{
                data: [initialValue, 100 - initialValue],
                backgroundColor: ['#FF6384', '#36A2EB']
            }]
        },
        options: {
            cutout: '70%',
            responsive: true,
            plugins: {
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return context.label + ': ' + context.parsed + '%';
                        }
                    }
                }
            }
        },
        plugins: [{
          id: 'centerText',
          beforeDraw: function(chart) {
              const width = chart.width,
                    height = chart.height,
                    ctx = chart.ctx;
              ctx.restore();
              
              const fontSize = (height / 10).toFixed(2);
              ctx.font = fontSize + "px Arial";
              ctx.textBaseline = "middle";
              ctx.textAlign = "center";
  
              // Get the percentage value
              const text = chart.data.datasets[0].data[0] + "%";
              const textX = width / 2;
              const textY = height / 2;
  
              ctx.fillStyle = "#333"; // Text color
              ctx.fillText(text, textX, textY);
              ctx.save();
          }
      }]
    });
}

function createGaugeChart(ctx, initialValue, maxValue, unit) {
    return new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Temperature'],
            datasets: [{
                data: [initialValue, maxValue - initialValue],
                backgroundColor: ['#FF5733', '#E0E0E0']
            }]
        },
        options: {
            cutout: '70%',
            responsive: true,
            plugins: {
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return context.parsed + '°C';
                        }
                    }
                }
            }
        },
        plugins: [{
          id: 'centerText',
          beforeDraw: function(chart) {
              const width = chart.width,
                    height = chart.height,
                    ctx = chart.ctx;
              ctx.restore();
              
              const fontSize = (height / 10).toFixed(2);
              ctx.font = fontSize + "px Arial";
              ctx.textBaseline = "middle";
              ctx.textAlign = "center";
  
              // Get the percentage value
              const text = chart.data.datasets[0].data[0] + "°C";
              const textX = width / 2;
              const textY = height / 2;
  
              ctx.fillStyle = "#333"; // Text color
              ctx.fillText(text, textX, textY);
              ctx.save();
          }
      }]
    });
}

// Get the canvas contexts for each chart.
const diskCtx = document.getElementById('diskChart').getContext('2d');
const gpuTempCtx = document.getElementById('gpuTempChart').getContext('2d');

const cpuCtx = document.getElementById('cpuChart').getContext('2d');
const gpuCtx = document.getElementById('gpuChart').getContext('2d');
const memoryCtx = document.getElementById('memoryChart').getContext('2d');

// Create the charts with initial values.
const diskChart = createDonutChart(diskCtx, 0);
const gpuTempChart = createGaugeChart(gpuTempCtx, 30, 100, '°C');

const cpuChart = createDonutChart(cpuCtx, 0);
const gpuChart = createDonutChart(gpuCtx, 0);
const memoryChart = createDonutChart(memoryCtx, 0);

// Function to update the charts with new data.
function updateCharts(data) {
    diskChart.data.datasets[0].data = [data.disk, 100 - data.disk];
    diskChart.update();

    gpuTempChart.data.datasets[0].data = [data.gpu_temp, 100 - data.gpu_temp];
    gpuTempChart.update();

    cpuChart.data.datasets[0].data = [data.cpu, 100 - data.cpu];
    cpuChart.update();

    gpuChart.data.datasets[0].data = [data.gpu, 100 - data.gpu];
    gpuChart.update();

    memoryChart.data.datasets[0].data = [data.memory, 100 - data.memory];
    memoryChart.update();
}

// Function to fetch metrics from the Flask backend.
function fetchMetrics() {
    fetch('/metrics')
        .then(response => response.json())
        .then(data => {
            updateCharts(data);
        })
        .catch(error => console.error('Error fetching metrics:', error));
}

// Fetch new metrics every 5 seconds.
setInterval(fetchMetrics, 5000);
fetchMetrics();

function usageToColor(percent) {
  // 120 (green) to 0 (red)
  const hue = Math.max(0, 120 - percent * 1.2);
  return `hsl(${hue}, 100%, 40%)`;
}

function updateStats() {
  fetch('/api/stats')
    .then(res => res.json())
    .then(data => {
      // CPU
      const cpuPercent = data.cpu;
      const cpuBar = document.getElementById('cpu-bar');
      cpuBar.style.width = `${cpuPercent}%`;
      cpuBar.innerText = `${cpuPercent.toFixed(1)}%`;
      cpuBar.style.backgroundColor = usageToColor(cpuPercent);
      document.getElementById('cpu-used-text').innerText = `${cpuPercent.toFixed(1)}% used`;

      // Memory
      const memPercent = data.memory.used_percent;
      const memBar = document.getElementById('mem-bar');
      memBar.style.width = `${memPercent}%`;
      memBar.innerText = `${memPercent.toFixed(1)}%`;
      memBar.style.backgroundColor = usageToColor(memPercent);
      document.getElementById('mem-used-text').innerText =
        `${memPercent.toFixed(1)}% used (${data.memory.used_gb} GB / ${data.memory.total_gb} GB)`;

      // Disk
      const diskPercent = data.disk.used_percent;
      const diskBar = document.getElementById('disk-bar');
      diskBar.style.width = `${diskPercent}%`;
      diskBar.innerText = `${diskPercent.toFixed(1)}%`;
      diskBar.style.backgroundColor = usageToColor(diskPercent);
      document.getElementById('disk-used-text').innerText =
        `${diskPercent.toFixed(1)}% used (${data.disk.used_gb} GB / ${data.disk.total_gb} GB)`;
    });
}

setInterval(updateStats, 10000);
updateStats();

const modal         = document.getElementById('processModal-BC');
const modalTitle    = document.getElementById('modalTitle-BC');
const processList   = document.getElementById('processList-BC');
const closeModalBtn = document.getElementById('closeModal-BC');

// Utility function to display the modal.
function showProcessModal(title, processes, resource) {
    modalTitle.textContent = title;
    processList.innerHTML = '';  // Clear previous items

    if (processes.length === 0) {
        const li = document.createElement('li');
        li.textContent = 'No processes found.';
        processList.appendChild(li);
    } else {
        processes.forEach(proc => {
            const li = document.createElement('li');
            if (resource === 'gpu') {
                li.textContent = `PID: ${proc.pid}, Name: ${proc.name}, GPU Memory: ${proc.gpu_memory_usage} MB`;
            } else if (resource === 'cpu') {
                li.textContent = `PID: ${proc.pid}, Name: ${proc.name}, CPU: ${proc.cpu_percent}%`;
            } else if (resource === 'memory') {
                li.textContent = `PID: ${proc.pid}, Name: ${proc.name}, Memory: ${proc.memory_percent.toFixed(2)}%`;
            }
            processList.appendChild(li);
        });
    }
    modal.style.display = 'flex';
}

// Function to fetch and show process details for a resource.
function fetchAndShowProcesses(resource) {
    let endpoint = '';
    let title = '';

    if (resource === 'cpu') {
        endpoint = '/processes/cpu';
        title = 'Top CPU Processes';
    } else if (resource === 'memory') {
        endpoint = '/processes/memory';
        title = 'Top Memory Processes';
    } else if (resource === 'gpu') {
        endpoint = '/processes/gpu';
        title = 'GPU Processes';
    }

    fetch(endpoint)
      .then(response => response.json())
      .then(data => {
          // The API returns an object with key "processes"
          showProcessModal(title, data.processes || [], resource);
      })
      .catch(error => console.error('Error fetching process data:', error));
}

// Attach click event listeners to the charts (using the updated IDs).
document.getElementById('cpuChart').addEventListener('click', function() {
    fetchAndShowProcesses('cpu');
});

document.getElementById('memoryChart').addEventListener('click', function() {
    fetchAndShowProcesses('memory');
});

document.getElementById('gpuChart').addEventListener('click', function() {
    fetchAndShowProcesses('gpu');
});

// Close the modal when the close button is clicked.
closeModalBtn.addEventListener('click', function() {
    modal.style.display = 'none';
});

// Optional: close modal if clicking outside of modal content.
window.addEventListener('click', function(event) {
    if (event.target === modal) {
        modal.style.display = 'none';
    }
});

let allLogs = []; // Store all logs globally for filtering

function fetchAllLogs() {
  console.log("Fetching firewall, web‐filter, and login logs...");

  Promise.all([
    fetch('/api/get_firewall_logs').then(res => res.json()),
    fetch('/api/get_webfilter_logs').then(res => res.json()),
    fetch('/api/login_events').then(res => res.json())
  ])
  .then(([firewallLogs, webFilterLogs, loginEvents]) => {
    // Combine all three sources
    const combinedLogs = [
      ...firewallLogs,
      ...webFilterLogs,
      ...loginEvents
    ];

    // Sort by timestamp descending (latest first)
    combinedLogs.sort((a, b) =>
      new Date(b.timestamp) - new Date(a.timestamp)
    );

    // Store globally for search/filter
    allLogs = combinedLogs;

    // Render into your table
    displayLogs(allLogs);
  })
  .catch(err => {
    console.error('Error fetching logs:', err);
  });
}


function displayLogs(logs) {
  const tableBody = document.getElementById('logs-table');
  tableBody.innerHTML = '';

  if (logs.length === 0) {
    tableBody.innerHTML = '<tr><td colspan="2">No logs found</td></tr>';
    return;
  }

  logs.forEach(log => {
    const row = document.createElement('tr');

    const timestampCell = document.createElement('td');
    timestampCell.textContent = log.timestamp;
    row.appendChild(timestampCell);

    const descriptionCell = document.createElement('td');
    descriptionCell.textContent = log.description;
    row.appendChild(descriptionCell);

    tableBody.appendChild(row);
  });
}

// Search function
function searchLogs() {
  const searchText = document.getElementById('search-input-log').value.trim().toLowerCase();
  
  if (!searchText) {
    displayLogs(allLogs); // Show all logs if search box is empty
    return;
  }

  const filteredLogs = allLogs.filter(log =>
    log.description.toLowerCase().includes(searchText)
  );

  displayLogs(filteredLogs);
}

// Filter by date function
function filterLogsByDate() {
  const selectedDate = document.getElementById('date-filter').value;
  
  if (!selectedDate) {
    alert("Please select a date.");
    return;
  }

  const filteredLogs = allLogs.filter(log =>
    log.timestamp.startsWith(selectedDate)
  );
  displayLogs(filteredLogs);
}

// Initial fetch
fetchAllLogs();

// Fetch logs every 5 seconds
setInterval(fetchAllLogs, 60000);

// Attach event listeners to buttons
document.getElementById('refresh-button-log').addEventListener('click', fetchAllLogs);
document.getElementById('search-input-log').addEventListener('input', searchLogs);
document.getElementById('filter-button-log').addEventListener('click', filterLogsByDate);



  // Start monitoring button
  document.getElementById('start-monitoring').addEventListener('click', function () {
    fetch('/start-monitoring')
      .then(response => response.json())
      .then(data => {
        if (data.status === 'started') {
          alert('Anomaly detection started. Monitoring for anomalous packets...');
        } else {
          alert('Failed to start anomaly detection.');
        }
      })
      .catch(error => {
        console.error('Error starting anomaly detection:', error);
      });
  });

  // Stop monitoring button
  document.getElementById('stop-monitoring').addEventListener('click', function () {
    fetch('/stop-monitoring')
      .then(response => response.json())
      .then(data => {
        if (data.status === 'stopped') {
          alert('Anomaly detection stopped.');
        } else {
          alert('Failed to stop anomaly detection.');
        }
      })
      .catch(error => {
        console.error('Error stopping anomaly detection:', error);
      });
  });

  // Fetch and display anomalies
  function fetchAnomalies() {

    const attackDescriptions = {
      "DNSCat2": "A DNS tunneling tool used to establish covert channels for data exfiltration and remote control.",
      "dns2tcp": "Enables TCP traffic over DNS to bypass firewall restrictions, often used for stealthy communication.",
      "Iodine": "Tunnels IPv4 traffic over DNS, allowing attackers to bypass security controls and exfiltrate data.",
      "Recon": "Involves scanning and probing network services to map topology or find vulnerabilities.",
      "DoS": "Denial of Service attack that floods resources to disrupt normal service availability.",
      "BruteForce": "Repeated login attempts to crack authentication credentials, commonly targeting weak accounts.",
      "Mirai": "Botnet malware targeting IoT devices to launch large-scale DDoS attacks.",
      "Web-based": "Includes attacks like XSS or SQL injection aimed at exploiting web application vulnerabilities.",
      "DDoS": "Distributed attack using multiple sources to overwhelm and shut down a network or service.",
      "Neris": "Malware generating command-and-control traffic to simulate botnet behavior and network infiltration.",
      "Htbot": "Uses compromised hosts to make web requests, hiding malicious activity behind normal HTTP traffic.",
      "Cridex": "Banking Trojan used to steal financial information and spread to other systems within a network.",
      "Nsis-ay": "A dropper Trojan that installs other malware components silently on the victim’s system.",
      "Shifu": "Steals banking credentials, uses advanced evasion techniques, and targets Japanese financial institutions.",
      "Zeus": "One of the most widespread banking Trojans, known for stealing login credentials through keylogging.",
      "Miuref": "Backdoor malware that allows remote access and executes commands issued by attackers.",
      "Geodo": "Spambot that spreads banking malware like Emotet through malicious attachments and links.",
      "Virut": "Polymorphic virus used to infect executables and join victim machines to a botnet.",
      "Tinba": "Tiny banking Trojan focused on intercepting browser sessions to steal sensitive user data.",
      "Torrent": "P2P file-sharing over VPN, commonly used to evade detection of unauthorized content distribution.",
      "Spotify": "Music streaming over VPN, potentially masking bandwidth misuse or hidden data tunneling.",
      "Vimeo": "Video streaming via VPN, which may be abused to obscure illicit traffic patterns.",
      "Youtube": "Encrypted video traffic routed through VPN, potentially used to hide malicious payload exchanges.",
      "Netflix": "VPN-masked high-bandwidth streaming that could be misused to conceal covert data transfers.",
      "Email": "Email communication over VPN, which can be exploited for hidden phishing, malware delivery, or data leakage.",
      "ICQ": "Legacy messaging service over VPN, vulnerable to abuse due to outdated protocols and weak security.",
      "Facebook": "Social media traffic over VPN, used to bypass access controls or enable covert message exchanges.",
      "AIM": "Obsolete messaging protocol tunneled via VPN, potentially used for undetected data exchange.",
      "Hangouts": "Google chat traffic over VPN, may carry encoded messages or malicious links while avoiding scrutiny.",
      "Skype": "VoIP and messaging traffic over VPN, used for encrypted C2 communications or social engineering.",
      "VoIPBuster": "Voice communication app tunneled through VPN, potentially part of anonymized botnet or fraud channels.",
      "SFTP": "Secure file transfer over VPN, possibly used to exfiltrate data under encrypted and anonymized cover.",
      "FTPS": "Encrypted file transfer protocol through VPN, hiding unauthorized or malicious data exchanges.",
      "Streaming": "Traffic routed through the Tor network, potentially used to mask the exfiltration of data disguised as media streams.",
      "Browsing": "Tor-based web browsing that may be used to anonymously access restricted or illicit websites.",
      "Chat": "Encrypted chat traffic over Tor, which can facilitate covert communication channels for cybercriminals.",
      "TraP2P": "Peer-to-peer protocols tunneled via Tor, often used to hide illegal file sharing or botnet communication.",
      "VoIP": "Voice-over-IP calls through Tor, enabling anonymized conversations that may be part of criminal coordination.",
      "FileTransfer": "File transfers routed via Tor, likely to evade inspection and facilitate data exfiltration or malware delivery."
      };

    fetch('/get-anomalies')
      .then(response => response.json())
      .then(data => {
        const anomaliesBody = document.getElementById('anomalies-body');
        anomaliesBody.innerHTML = '';
  
        data.anomalies.forEach(anomaly => {
          const localTime = new Date(anomaly.timestamp).toLocaleString();

          const attackDesc = attackDescriptions[anomaly.attack_type] || "N/A";
          
          // For each anomaly, we create a <tr>:
          const row = document.createElement('tr');
          
          // We'll store source/dest IP in data attributes
          row.innerHTML = `
            <td>${localTime}</td>
            <td>${anomaly.reconstruction_error.toFixed(4)}</td>
            <td>
              <div class="hex-code-cell">
                ${anomaly.hex_data}
                </div>
            </td>
            <td>${anomaly.source_ip}</td>
            <td>${anomaly.destination_ip}</td>
            <td>${anomaly.attack_type}</td>
            <td>${attackDesc}</td>
            <td>
              <!-- By default, let’s show an "Unblock" button 
                   if we detect from the server that it's still blocked.
                   Or show "Block" if it's unblocked. 
                   But for simplicity, let's assume it's "Unblock" 
                   unless we do an extra check. -->
              <button 
                class="unblock-btn"
                data-source-ip="${anomaly.source_ip}" 
                data-destination-ip="${anomaly.destination_ip}"
              >
                Unblock
              </button>
            </td>
          `;
          anomaliesBody.appendChild(row);
        });
  
        // Attach event listeners for all "Unblock" buttons
        document.querySelectorAll('.unblock-btn').forEach(button => {
          button.addEventListener('click', function () {
            const sourceIP = this.getAttribute('data-source-ip');
            const destinationIP = this.getAttribute('data-destination-ip');
        
            if (!sourceIP || !destinationIP) {
              alert('Source IP or Destination IP is missing.');
              return;
            }
        
            fetch('/unblock-packet', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ source_ip: sourceIP, destination_ip: destinationIP })
            })
            .then(response => response.json())
            .then(data => {
              if (data.message) {
                alert(data.message);
                fetchAnomalies(); // Refresh table after unblocking
              } else {
                alert(data.error);
              }
            })
            .catch(error => {
              console.error('Error unblocking packet:', error);
            });
          });
        });
      });
  }
  
  

  // Poll the server for anomalies every 5 seconds
  setInterval(fetchAnomalies, 5000);

  // Initial fetch of anomalies on page load
  fetchAnomalies();
});


document.addEventListener('DOMContentLoaded', () => {
  const createPolicyButton = document.getElementById('create-policy-button');
  const policyModal = document.getElementById('policy-modal');
  const closeModal = document.getElementById('close-modal');
  const policyForm = document.getElementById('policy-form');
  const policyTable = document.querySelector('#policy-table tbody');
  const searchInput = document.getElementById('search-input');
  const searchButton = document.getElementById('search-button');
  const cancelBtn = document.querySelector('.cancel-btn'); // Cancel button
  const acceptBtn = document.getElementById("accept-btn");
  const denyBtn = document.getElementById("deny-btn");

  let policiesData = []; // Store fetched policies for filtering
  let selectedAction = "Allow"; // Default Action

  // Function to open the modal
  createPolicyButton.addEventListener('click', () => {
      policyModal.style.display = 'block';
  });

  // Function to close the modal
  closeModal.addEventListener('click', () => {
      policyModal.style.display = 'none';
  });

  // Cancel Button - Close Modal without Submitting
  cancelBtn.addEventListener('click', () => {
      policyModal.style.display = 'none';
  });

  // Close the modal when clicking outside of it
  window.addEventListener('click', (event) => {
      if (event.target === policyModal) {
          policyModal.style.display = 'none';
      }
  });

  // Helper function to call the backend to disable a policy
async function disablePolicy(ruleName) {
  try {
    const response = await fetch('/api/disable_firewall_policy', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rule_name: ruleName })
    });
    const result = await response.json();
    if (result.success) {
      alert(`Policy "${ruleName}" disabled successfully!`);
      // Refresh the table
      fetchPolicies();
    } else {
      alert('Error disabling policy: ' + (result.message || 'Unknown error'));
    }
  } catch (error) {
    console.error(error);
    alert('Error disabling policy');
  }
}

// Helper function to call the backend to delete a policy
async function deletePolicy(ruleName) {
  try {
    const response = await fetch('/api/delete_firewall_policy', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rule_name: ruleName })
    });
    const result = await response.json();
    if (result.success) {
      alert(`Policy "${ruleName}" deleted successfully!`);
      // Refresh the table
      fetchPolicies();
    } else {
      alert('Error deleting policy: ' + (result.message || 'Unknown error'));
    }
  } catch (error) {
    console.error(error);
    alert('Error deleting policy');
  }
}

  // Function to render policies in the table
  const renderPolicies = (filteredPolicies) => {
    policyTable.innerHTML = ''; // Clear the table
  
    if (filteredPolicies.length > 0) {
      filteredPolicies.forEach((policy) => {
        // Create main row
        const row = document.createElement('tr');
        row.innerHTML = `
          <td>${policy.RuleName || 'N/A'}</td>
          <td>${policy.LocalIP || 'N/A'}</td>
          <td>${policy.RemoteIP || 'N/A'}</td>
          <td>${policy.Direction || 'N/A'}</td>
          <td>${policy.Action || 'N/A'}</td>
          <td>${policy.Protocol && policy.Protocol !== 'Any' ? policy.Protocol : 'N/A'}</td>
          <td>${policy.LocalPort && policy.LocalPort !== 'Any' ? policy.LocalPort : 'N/A'}</td>
          <td>${policy.Enabled || 'N/A'}</td>
        `;
  
        // Create detail row (hidden by default)
        const detailRow = document.createElement('tr');
        detailRow.classList.add('detail-row');
        detailRow.style.display = 'none';
  
        // We'll create a single cell that spans all columns
        const detailCell = document.createElement('td');
        detailCell.colSpan = 8;
  
        // Add the two action buttons
        detailCell.innerHTML = `
          <div class="action-buttons">
            <button class="disable-btn">Disable</button>
            <button class="delete-btn" style="background-color:red;color:white;">Delete</button>
          </div>
        `;
  
        detailRow.appendChild(detailCell);
  
        // When user clicks on the main row, toggle detail row
        row.addEventListener('click', () => {
          if (detailRow.style.display === 'none') {
            detailRow.style.display = 'table-row';
          } else {
            detailRow.style.display = 'none';
          }
        });
  
        // Attach event listeners to the disable and delete buttons
        const disableBtn = detailCell.querySelector('.disable-btn');
        const deleteBtn = detailCell.querySelector('.delete-btn');
  
        disableBtn.addEventListener('click', (e) => {
          // Prevent the row click from re-toggling
          e.stopPropagation();
          disablePolicy(policy.RuleName);
        });
  
        deleteBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          // Confirm deletion
          if (confirm(`Are you sure you want to delete policy "${policy.RuleName}"?`)) {
            deletePolicy(policy.RuleName);
          }
        });
  
        // Append both rows to the table
        policyTable.appendChild(row);
        policyTable.appendChild(detailRow);
      });
    } else {
      policyTable.innerHTML = '<tr><td colspan="8">No policies found</td></tr>';
    }
  };

  // Fetch and store policies
  const fetchPolicies = async () => {
      try {
          const response = await fetch('/api/firewall_policies');
          if (!response.ok) throw new Error(`HTTP error! Status: ${response.status}`);
          policiesData = await response.json(); // Store fetched policies
          renderPolicies(policiesData); // Render them initially
      } catch (error) {
          console.error('Error fetching policies:', error);
          policyTable.innerHTML = '<tr><td colspan="8">Error loading policies</td></tr>';
      }
  };

  // Search Function (Search by Rule Name or Port)
  const searchPolicies = () => {
      const searchTerm = searchInput.value.toLowerCase();

      const filteredPolicies = policiesData.filter(policy => {
          const ruleName = policy.RuleName ? policy.RuleName.toLowerCase() : '';
          const port = policy.LocalPort ? policy.LocalPort.toString().toLowerCase() : ''; // Ensure Port is treated as a string
          
          return ruleName.includes(searchTerm) || port.includes(searchTerm);
      });

      renderPolicies(filteredPolicies);
  };

  // Attach event listener to search button
  searchButton.addEventListener('click', searchPolicies);

  // Enable real-time searching as user types
  searchInput.addEventListener('input', searchPolicies);

  // Toggle Buttons for Action Selection (Allow/Deny)
  acceptBtn.addEventListener("click", function () {
      acceptBtn.classList.add("active");
      denyBtn.classList.remove("active");
      selectedAction = "Allow"; // Set action to Allow
  });

  denyBtn.addEventListener("click", function () {
      denyBtn.classList.add("active");
      acceptBtn.classList.remove("active");
      selectedAction = "Deny"; // Set action to Deny
  });

  // Add a new policy
  policyForm.addEventListener('submit', async (event) => {
      event.preventDefault();

      const newPolicy = {
          rule_name: document.getElementById('policy-name').value,
          source_ip: document.getElementById('source-ip').value,
          destination_ip: document.getElementById('destination-ip').value,
          port: document.getElementById('port').value,
          protocol: document.getElementById('protocol').value,
          direction: document.getElementById('direction').value,
          action: selectedAction, // Use selected Action value
      };

      try {
          const response = await fetch('/api/add_firewall_policy', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(newPolicy),
          });

          const result = await response.json();
          if (result.success) {
              alert('Policy added successfully!');
              policyModal.style.display = 'none'; // Close the modal
              fetchPolicies(); // Refresh the table
              policyForm.reset();
              selectedAction = "Allow"; // Reset action to default
              acceptBtn.classList.add("active");
              denyBtn.classList.remove("active");
          } else {
              alert('Error adding policy: ' + result.message);
          }
      } catch (error) {
          console.error('Error adding policy:', error);
          alert('Error adding policy');
      }
  });

  // Fetch and display policies on page load
  fetchPolicies();

  const refreshButton = document.getElementById('refresh-button');

  // Attach event listener to the refresh button
  refreshButton.addEventListener('click', fetchPolicies);
});

const refreshButton = document.getElementById('refresh-button');

// Attach event listener to the refresh button
refreshButton.addEventListener('click', fetchPolicies);

disableBtn.addEventListener('click', (e) => {
  e.stopPropagation();
  disablePolicy(policy.RuleName)
    .then(() => {
      fetchPolicies(); // Re-fetch to see updated enable status
    });
});


document.getElementById('unblock-button').addEventListener('click', async function () {
  // Grab the URL from the same text box
  const urlToUnblock = document.getElementById('filter-url').value;

  // Make a POST request to /unblock-url/<the URL>
  const response = await fetch('/unblock-url/' + encodeURIComponent(urlToUnblock), {
    method: 'POST'
  });

  const data = await response.json();
  alert(data.message);
});

document.getElementById("filter-form").addEventListener("submit", async (event) => {
  event.preventDefault();  // Stop the normal form submission
  const formData = new FormData(event.target);

  const response = await fetch("/apply-filter", {
    method: "POST",
    body: formData
  });
  const result = await response.json();

  if (result.status === "success") {
    alert(result.message); // or show it on the page
  } else {
    alert("Error: " + result.message);
  }
});