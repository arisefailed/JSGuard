/*
       _  _____  _____                     _ 
      | |/ ____|/ ____|                   | |
      | | (___ | |  __ _   _  __ _ _ __ __| |
  _   | |\___ \| | |_ | | | |/ _` | '__/ _` |
 | |__| |____) | |__| | |_| | (_| | | | (_| |
  \____/|_____/ \_____|\__,_|\__,_|_|  \__,_|
  Made with <3 by arisefailed
                                             
[!] JSGuard - Advanced Strong Layer-4 DDoS Protection
[?] Github: https://github.com/arisefailed
*/

const express = require('express');
const rateLimit = require('express-rate-limit');
const chalk = require('chalk');
const fs = require('fs');
const path = require('path');
const moment = require('moment');
const requestIp = require('request-ip');
const figlet = require('figlet');
const bodyParser = require('body-parser');
const helmet = require('helmet');
const hpp = require('hpp');
const toobusy = require('toobusy-js');
const inquirer = require('inquirer');
const ora = require('ora');
const Conf = require('conf');
const gradient = require('gradient-string');

// Initialize configuration
const config = new Conf({
    cwd: path.join(__dirname, 'config'),
    configName: 'config'
});

// Security Constants
const PAYLOAD_SIZE_LIMIT = 1024 * 100;
const MAX_CONCURRENT_CONNECTIONS = 25;
const CONNECTION_TIMEOUT = 5000;
const SUSPICIOUS_PATTERNS = [
    // SQL Injection
    /union\s+select/i,
    /information_schema/i,
    /concat\s*\(/i,
    /group\s+by/i,
    /order\s+by/i,
    
    // XSS
    /<script>/i,
    /on\w+\s*=/i,  // onerror, onload, etc.
    /javascript:/i,
    /data:/i,
    
    // Path Traversal
    /\.\.\/|\.\.\\/i,
    /\/etc\//i,
    /\/proc\//i,
    /\/var\/log/i,
    
    // Command Injection
    /exec\s*\(/i,
    /eval\s*\(/i,
    /system\s*\(/i,
    /shell_exec/i,
    /passthru/i,
    /\|\s*cat\s/i,
    /\|\s*wget\s/i,
    /\|\s*curl\s/i,
    
    // Client-Side
    /(document|window)\./i,
    /localStorage/i,
    /sessionStorage/i,
    /indexedDB/i,
    
    // File Upload
    /\.php$/i,
    /\.asp$/i,
    /\.jsp$/i,
    /\.cgi$/i,
    /\.exe$/i,
    
    // Common Attacks
    /(<|%3C).*script.*(>|%3E)/i,
    /(=|%3D).*(javascript|vbscript):/i,
    /alert\s*\(/i,
    /sql\s*injection/i,
    /\/etc\/passwd/i,
    /\/win.ini/i,
    /\.htaccess/i,
    
    // NoSQL Injection
    /\$where/i,
    /\$regex/i,
    /\$ne/i,
    /\$gt/i,
    
    // Template Injection
    /\$\{.*\}/i,
    /\{\{.*\}\}/i,
    
    // SSRF
    /^(http|https):\/\/localhost/i,
    /^(http|https):\/\/127\./i,
    /^(http|https):\/\/192\.168\./i,
    /^(http|https):\/\/10\./i,
    
    // Log4j
    /\$\{jndi:/i,
    /\$\{env:/i,
    /\$\{sys:/i,

    // Botnet & C2 Patterns
    /.*\.onion$/i,
    /.*\.tor2web\./i,
    /.*\.exit$/i,
    /.*\.bitmessage\./i,
    /.*\.i2p$/i,
    
    // Mirai Patterns
    /\/bin\/busybox/i,
    /\/dev\/watchdog/i,
    /\/dev\/misc\/watchdog/i,
    /\/dev\/FTWDT101/i,
    /ECCHI/i,
    /MIRAI/i,
    /TSUNAMI/i,
    /QBOT/i,
    
    // Common C2 Patterns
    /reverse_tcp/i,
    /reverse_http/i,
    /reverse_https/i,
    /meterpreter/i,
    /empire/i,
    /cobaltstrike/i,
    /beacon/i
];

// Additional security settings
const SECURITY_SETTINGS = {
    maxRequestSize: '100kb',
    maxFileSize: '5mb',
    rateLimitWindow: 60 * 1000,
    rateLimitMax: 60,
    maxHeaderSize: 8192,
    maxUrlLength: 2048,
    maxParameterCount: 50,
    maxCookieCount: 20,
    suspiciousIPThreshold: 5,
    blacklistThreshold: 10,
    requestBurstLimit: 10,
    burstWindow: 1000,
    maxSessionAge: 3600000,
    maxPayloadDepth: 5,
    botnetProtection: {
        maxConnectionsPerIP: 10,
        suspiciousPortsList: [
            23, 2323, 23231, 23232,  // Telnet ports commonly used by Mirai
            48101, 37215, 52869,     // Known vulnerable ports
            6667, 7547               // IRC and TR-064 ports
        ],
        bannedUserAgents: [
            /(?:bot|crawler|spider|wget|curl)/i,
            /python-requests/i,
            /zgrab/i,
            /masscan/i
        ]
    },
    ddosProtection: {
        requestThreshold: 30,
        timeWindow: 1000,
        blockDuration: 3600000, // 1 hour
        maxRequestsPerIP: 300,
        maxRequestBurst: 20,
        burstTimeWindow: 500,
        challengeTimeout: 30000,
        proxyCheck: true,
        ipReputationCheck: true,
        ddosProtection: {
            // ... existing ddos settings ...
            layer4Protection: {
                enabled: true,
                tcpProtection: {
                    maxSynPerSecond: 30,
                    maxAckPerSecond: 50,
                    maxFinPerSecond: 20,
                    synCookies: true,
                    synBacklog: 256,
                    tcpTimestamps: true,
                    tcpSynRetries: 3,
                    blacklistThreshold: 100,
                    synFloodDetection: true,
                    ackFloodDetection: true,
                    finFloodDetection: true,
                    pshFloodDetection: true,
                    rstFloodDetection: true,
                    nullFloodProtection: true
                },
                udpProtection: {
                    maxPacketsPerSecond: 100,
                    maxBytesPerSecond: 1024 * 1024, // 1MB
                    amplificationFactor: 10,
                    fragmentationProtection: true,
                    portScanDetection: true,
                    floodDetection: true,
                    blacklistThreshold: 50
                },
                icmpProtection: {
                    enabled: true,
                    maxPacketsPerSecond: 10,
                    pingOfDeathProtection: true,
                    smurf: true,
                    blacklistThreshold: 20
                },
                connectionTracking: {
                    enabled: true,
                    maxConnectionsPerIP: 50,
                    connectionTimeout: 30000,
                    trackStates: true,
                    validateSequence: true
                }
            }
        },
        requestScoring: {
            suspiciousHeaders: 2,
            invalidPayload: 3,
            rapidRequests: 2,
            bannedUserAgent: 4,
            suspiciousPath: 2
        },
        thresholds: {
            cpuUsage: 80,
            memoryUsage: 85,
            requestScore: 10
        },
        amplificationProtection: {
            maxPacketSize: 1500, // Maximum UDP packet size
            maxAmplificationFactor: 10,
            ssdpProtection: true,
            nptProtection: true,
            dnsAmplificationProtection: true,
            chargenProtection: true,
            quotaTimeWindow: 1000,
            quotaMaxPackets: 100,
            blacklistThreshold: 5,
            suspiciousPortsList: [
                1900,  // SSDP
                123,   // NTP
                53,    // DNS
                19,    // CHARGEN
                137,   // NetBIOS
                161,   // SNMP
                389,   // CLDAP
                11211  // Memcached
            ]
        },
        networkProtection: {
            tcpSynFloodProtection: true,
            udpFloodProtection: true,
            icmpFloodProtection: true,
            maxTcpConnections: 100,
            maxUdpPackets: 100,
            maxIcmpPackets: 50,
            synCookies: true,
            connectionTracking: true,
            tcpRateLimit: {
                window: 1000,
                maxConnections: 50
            },
            udpRateLimit: {
                window: 1000,
                maxPackets: 50
            }
        }
    }
};

// Initialize tracking systems
let blacklistedIPs = new Set();
const requestCounts = new Map();
const suspiciousIPs = new Map();
const connectionCounts = new Map();
const requestPatterns = new Map();
const lastRequestTimes = new Map();
const connectionTracking = new Map();
const tcpStates = new Map();
const udpStates = new Map();

// Loading animation stages
const loadingStages = [
    { text: 'Initializing security modules...', duration: 1000 },
    { text: 'Loading protection layers...', duration: 800 },
    { text: 'Configuring firewall...', duration: 1200 },
    { text: 'Starting monitoring system...', duration: 900 },
    { text: 'Preparing defense mechanisms...', duration: 1000 }
];

// Display ASCII Art
const displayBanner = () => {
    return new Promise((resolve) => {
        figlet('JSGuard', {
            font: 'Elite',
            horizontalLayout: 'fitted'
        }, (err, data) => {
            if (!err) {
                console.clear();
                console.log(gradient(['#00FF00', '#00FFFF', '#0000FF']).multiline(data));
                console.log(chalk.green('='.repeat(50)));
                resolve();
            }
        });
    });
};

// Loading animation
const simulateLoading = async () => {
    for (const stage of loadingStages) {
        const spinner = ora({
            text: stage.text,
            color: 'cyan',
            spinner: 'dots'
        }).start();

        await new Promise(resolve => setTimeout(resolve, stage.duration));
        spinner.succeed(chalk.green(stage.text));
    }
};

// Configuration prompt
const promptConfig = async () => {
    if (config.has('host') && config.has('port')) {
        const spinner = ora('Loading saved configuration...').start();
        await new Promise(resolve => setTimeout(resolve, 1000));
        spinner.succeed('Configuration loaded successfully!');
        return {
            host: config.get('host'),
            port: config.get('port')
        };
    }

    console.log(chalk.yellow('\n📝 Initial Setup Required'));
    const answers = await inquirer.prompt([
        {
            type: 'input',
            name: 'host',
            message: 'IP Address to host:',
            default: '0.0.0.0'  // Changed from 'localhost' to '0.0.0.0'
        },
        {
            type: 'input',
            name: 'port',
            message: 'Server port to host:',
            default: '80',      // Changed from '3000' to '80'
            validate: input => !isNaN(input) && input > 0 && input < 65536
        }
    ]);

    const spinner = ora('Saving configuration...').start();
    config.set(answers);
    await new Promise(resolve => setTimeout(resolve, 1000));
    spinner.succeed('Configuration saved successfully!');

    return answers;
};

// Enhanced logging functions
const logRequest = (req, res, next) => {
    const clientIP = requestIp.getClientIp(req);
    const timestamp = moment().format('YYYY-MM-DD HH:mm:ss');
    const logData = {
        timestamp,
        ip: clientIP,
        method: req.method,
        path: req.path,
        userAgent: req.headers['user-agent']
    };
    
    console.log(chalk.blue.bold('📝 REQUEST:'));
    console.log(chalk.cyan(`[${timestamp}] ${req.method} ${req.path}`));
    console.log(chalk.gray(`IP: ${clientIP}`));
    
    fs.appendFileSync('logs/access.txt', JSON.stringify(logData) + '\n');
    next();
};

const logThreat = (message) => {
    const timestamp = moment().format('YYYY-MM-DD HH:mm:ss');
    const logData = {
        timestamp,
        message,
        serverLoad: toobusy.lag(),
        activeConnections: Array.from(connectionCounts.values()).reduce((a, b) => a + b, 0)
    };
    
    console.log(chalk.red.bold('⚠️ THREAT DETECTED:'));
    console.log(chalk.yellow(`[${timestamp}] ${message}`));
    
    fs.appendFileSync('logs/threats.txt', JSON.stringify(logData) + '\n');
};

const blacklistIP = (ip) => {
    blacklistedIPs.add(ip);
    fs.writeFileSync('data/blacklist.json', JSON.stringify(Array.from(blacklistedIPs)));
    logThreat(`IP Address ${ip} has been blacklisted`);
};

function calculateRequestScore(req) {
    let score = 0;
    const settings = SECURITY_SETTINGS.ddosProtection.requestScoring;

    // Check headers
    if (hasAbnormalHeaders(req.headers)) score += settings.suspiciousHeaders;
    
    // Check payload size and content
    if (req.body && JSON.stringify(req.body).length > PAYLOAD_SIZE_LIMIT) {
        score += settings.invalidPayload;
    }

    // Check request path complexity
    if (req.path.split('/').length > 10 || req.path.length > 255) {
        score += settings.suspiciousPath;
    }

    return score;
}

function getRecentRequests(ip, now) {
    const recentRequests = requestCounts.get(ip) || 0;
    const lastRequestTime = lastRequestTimes.get(ip) || 0;
    
    if (now - lastRequestTime > SECURITY_SETTINGS.ddosProtection.timeWindow) {
        requestCounts.set(ip, 1);
        return 1;
    }
    
    return recentRequests;
}

function getBurstCount(ip, now) {
    const patterns = requestPatterns.get(ip) || new Set();
    return patterns.size;
}

function hasAbnormalHeaders(headers) {
    const suspicious = [
        'x-forwarded-for',
        'forwarded',
        'via',
        'x-real-ip'
    ];
    return suspicious.some(header => headers[header]);
}

function getTcpConnectionCount(ip) {
    return connectionCounts.get(`tcp:${ip}`) || 0;
}

function getConnectionTracking(ip) {
    const tracking = connectionTracking.get(ip) || {
        connections: 0,
        lastReset: Date.now()
    };
    return tracking;
}

function getTcpState(ip) {
    const state = tcpStates.get(ip) || {
        synCount: 0,
        ackCount: 0,
        finCount: 0,
        lastReset: Date.now()
    };
    return state;
}

function getUdpState(ip) {
    const state = udpStates.get(ip) || {
        packetsPerSecond: 0,
        bytesPerSecond: 0,
        lastReset: Date.now()
    };
    return state;
}

function validateTcpSequence(connection) {
    // Validate TCP sequence numbers and connection state
    return connection.established && 
           connection.remoteSequenceNumber > 0 && 
           connection.localSequenceNumber > 0;
}

// Initialize server
const initializeServer = async () => {
    // Create necessary directories
    ['logs', 'data', 'config'].forEach(dir => {
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir);
        }
    });

    // Load blacklist
    try {
        const blacklist = fs.readFileSync('data/blacklist.json');
        blacklistedIPs = new Set(JSON.parse(blacklist));
    } catch (err) {
        fs.writeFileSync('data/blacklist.json', '[]');
    }

    await displayBanner();
    await simulateLoading();
    const serverConfig = await promptConfig();

    const app = express();

    // Security middleware
    app.use(helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: ["'self'"],
                styleSrc: ["'self'"],
                imgSrc: ["'self'"],
                connectSrc: ["'self'"],
                fontSrc: ["'self'"],
                objectSrc: ["'none'"],
                mediaSrc: ["'self'"],
                frameSrc: ["'none'"],
                workerSrc: ["'none'"],    
                frameAncestors: ["'none'"], 
                formAction: ["'self'"],   
                manifestSrc: ["'none'"],  
                navigateTo: ["'none'"]
            }
        },
        crossOriginEmbedderPolicy: true,
        crossOriginOpenerPolicy: true,
        crossOriginResourcePolicy: { policy: "same-site" },
        dnsPrefetchControl: true,
        expectCt: true,
        frameguard: { action: 'deny' },
        hsts: true,
        ieNoOpen: true,
        noSniff: true,
        originAgentCluster: true,
        permittedCrossDomainPolicies: { permittedPolicies: 'none' },
        referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
        xssFilter: true
    }));
    app.use(hpp());
    app.use(bodyParser.json({ limit: '100kb' }));
    app.use(bodyParser.urlencoded({ extended: true, limit: '100kb' }));

    // Server stress check
    app.use((req, res, next) => {
        if (toobusy()) {
            logThreat('Server is under heavy load. Rejecting new requests.');
            return res.status(503).send('Server is under heavy load. Please try again later.');
        }
        next();
    });

    app.use(logRequest);

    // Security middleware
    app.use((req, res, next) => {
        const clientIP = requestIp.getClientIp(req);
        const userAgent = req.headers['user-agent'] || '';
        const now = Date.now();

        if (SECURITY_SETTINGS.ddosProtection.layer4Protection.enabled) {
            const connTrack = getConnectionTracking(clientIP);
            
            // TCP Flood Protection
            if (req.connection.type === 'tcp') {
                const tcpState = getTcpState(clientIP);
                
                if (tcpState.synCount > SECURITY_SETTINGS.ddosProtection.layer4Protection.tcpProtection.maxSynPerSecond ||
                    tcpState.ackCount > SECURITY_SETTINGS.ddosProtection.layer4Protection.tcpProtection.maxAckPerSecond) {
                    blacklistIP(clientIP);
                    logThreat(`TCP flood attack detected from ${clientIP}`);
                    return res.status(403).send('Access Denied');
                }
    
                // TCP-BYPASS Protection
                if (!validateTcpSequence(req.connection)) {
                    blacklistIP(clientIP);
                    logThreat(`TCP-BYPASS attempt detected from ${clientIP}`);
                    return res.status(403).send('Access Denied');
                }
            }
    
            // UDP Protection
            if (req.connection.type === 'udp') {
                const udpState = getUdpState(clientIP);
                
                if (udpState.packetsPerSecond > SECURITY_SETTINGS.ddosProtection.layer4Protection.udpProtection.maxPacketsPerSecond) {
                    blacklistIP(clientIP);
                    logThreat(`UDP flood attack detected from ${clientIP}`);
                    return res.status(403).send('Access Denied');
                }
            }
    
            // Connection State Tracking
            if (connTrack.connections > SECURITY_SETTINGS.ddosProtection.layer4Protection.connectionTracking.maxConnectionsPerIP) {
                blacklistIP(clientIP);
                logThreat(`Connection limit exceeded from ${clientIP}`);
                return res.status(403).send('Access Denied');
            }
        }

        if (req.connection.type === 'udp' && 
            SECURITY_SETTINGS.ddosProtection.amplificationProtection.suspiciousPortsList.includes(req.connection.remotePort)) {
            blacklistIP(clientIP);
            logThreat(`Amplification attack detected from ${clientIP}`);
            return res.status(403).send('Access Denied');
        }

        if (req.connection.type === 'tcp' && !req.connection.established) {
            const tcpConnections = getTcpConnectionCount(clientIP);
            if (tcpConnections > SECURITY_SETTINGS.ddosProtection.networkProtection.maxTcpConnections) {
                blacklistIP(clientIP);
                logThreat(`TCP flood detected from ${clientIP}`);
                return res.status(403).send('Access Denied');
            }
        }

        const requestScore = calculateRequestScore(req);
        const recentRequests = getRecentRequests(clientIP, now);
        const burstCount = getBurstCount(clientIP, now);

        if (requestScore >= SECURITY_SETTINGS.ddosProtection.thresholds.requestScore) {
            blacklistIP(clientIP);
            return res.status(403).send('Access Denied');
        }
    
        if (recentRequests > SECURITY_SETTINGS.ddosProtection.maxRequestsPerIP) {
            logThreat(`DDoS attempt detected from ${clientIP}`);
            blacklistIP(clientIP);
            return res.status(429).send('Rate limit exceeded');
        }
    
        if (burstCount > SECURITY_SETTINGS.ddosProtection.maxRequestBurst) {
            suspiciousIPs.set(clientIP, (suspiciousIPs.get(clientIP) || 0) + 3);
            if (suspiciousIPs.get(clientIP) > SECURITY_SETTINGS.suspiciousIPThreshold) {
                blacklistIP(clientIP);
                return res.status(403).send('Access Denied');
            }
        }

        const cpuUsage = process.cpuUsage().user / process.cpuUsage().system * 100;
        const memUsage = process.memoryUsage().heapUsed / process.memoryUsage().heapTotal * 100;
    
        if (cpuUsage > SECURITY_SETTINGS.ddosProtection.thresholds.cpuUsage || 
            memUsage > SECURITY_SETTINGS.ddosProtection.thresholds.memoryUsage) {
            logThreat('High resource usage detected - potential DDoS');
            return res.status(503).send('Server is under heavy load');
        }

        if (SECURITY_SETTINGS.botnetProtection.bannedUserAgents.some(pattern => pattern.test(userAgent))) {
            blacklistIP(clientIP);
            return res.status(403).send('Access Denied');
        }

        const clientPort = req.connection.remotePort;
        if (SECURITY_SETTINGS.botnetProtection.suspiciousPortsList.includes(clientPort)) {
            logThreat(`Suspicious port access from ${clientIP}:${clientPort}`);
            blacklistIP(clientIP);
            return res.status(403).send('Access Denied');
        }

        if (blacklistedIPs.has(clientIP)) {
            logThreat(`Blocked blacklisted IP: ${clientIP}`);
            return res.sendFile(path.join(__dirname, 'site', 'blocked.html'));
        }

        const currentConnections = connectionCounts.get(clientIP) || 0;
        if (currentConnections >= MAX_CONCURRENT_CONNECTIONS) {
            logThreat(`Connection limit exceeded from IP: ${clientIP}`);
            return res.status(429).send('Too Many Connections');
        }

        connectionCounts.set(clientIP, currentConnections + 1);
        const pattern = `${req.method}:${req.path}`;
        const patterns = requestPatterns.get(clientIP) || new Set();
        patterns.add(pattern);
        requestPatterns.set(clientIP, patterns);

        const payload = JSON.stringify({ ...req.body, ...req.query, ...req.params });
        if (SUSPICIOUS_PATTERNS.some(pattern => pattern.test(payload))) {
            blacklistIP(clientIP);
            return res.sendFile(path.join(__dirname, 'site', 'blocked.html'));
        }

        const lastRequest = lastRequestTimes.get(clientIP) || 0;
        if (lastRequest > 0 && (now - lastRequest) < 50) {
            suspiciousIPs.set(clientIP, (suspiciousIPs.get(clientIP) || 0) + 2);
            if (suspiciousIPs.get(clientIP) > 5) {
                blacklistIP(clientIP);
                return res.sendFile(path.join(__dirname, 'site', 'blocked.html'));
            }
        }
        lastRequestTimes.set(clientIP, now);

        const currentCount = requestCounts.get(clientIP) || 0;
        requestCounts.set(clientIP, currentCount + 1);
        if (currentCount > 50) {
            suspiciousIPs.set(clientIP, (suspiciousIPs.get(clientIP) || 0) + 1);
        }

        res.setTimeout(CONNECTION_TIMEOUT, () => {
            logThreat(`Connection timeout from ${clientIP}`);
            res.status(408).send('Request Timeout');
        });

        res.on('finish', () => {
            const count = connectionCounts.get(clientIP);
            if (count > 0) connectionCounts.set(clientIP, count - 1);
        });

        const connectionCount = connectionCounts.get(clientIP) || 0;
        if (connectionCount > SECURITY_SETTINGS.botnetProtection.maxConnectionsPerIP) {
            logThreat(`Potential botnet activity from ${clientIP}`);
            blacklistIP(clientIP);
            return res.status(403).send('Access Denied');
        }

        next();
    });

    // Rate limiter
    app.use(rateLimit({
        windowMs: 60 * 1000,
        max: 60,
        message: 'Too many requests, please try again later.',
        standardHeaders: true,
        legacyHeaders: false
    }));

    // Serve static files
    app.use(express.static('site'));

    // Routes
    app.get('/', (req, res) => {
        const clientIP = requestIp.getClientIp(req);
        if (blacklistedIPs.has(clientIP)) {
            res.sendFile(path.join(__dirname, 'site', 'blocked.html'));
        } else {
            res.sendFile(path.join(__dirname, 'site', 'index.html'));
        }
    });

    // Cleanup intervals
    setInterval(() => {
        requestCounts.clear();
        suspiciousIPs.clear();
        connectionCounts.clear();
        requestPatterns.clear();
        lastRequestTimes.clear();
        connectionTracking.clear();
        tcpStates.clear();
        udpStates.clear();
        Object.keys(connectionCounts).forEach(key => {
            if (key.startsWith('tcp:')) connectionCounts.delete(key);
        });
    }, 60 * 1000);

    // Start server
    app.listen(serverConfig.port, serverConfig.host, () => {
        console.log('\n' + chalk.green('='.repeat(50)));
        console.log(chalk.white.bold(`🛡️  Server running on http://${serverConfig.host}:${serverConfig.port}`));
        console.log(chalk.white.bold(`📝 Access Logging: ${chalk.green('Active')}`));
        console.log(chalk.white.bold(`⚠️ Threat Logging: ${chalk.green('Active')}`));
        console.log(chalk.white.bold(`🚫 DDoS Protection: ${chalk.green('Active')}`));
        console.log(chalk.white.bold(`⚔️  Blacklist System: ${chalk.green('Active')}`));
        console.log(chalk.white.bold(`🔍 Payload Analysis: ${chalk.green('Active')}`));
        console.log(chalk.white.bold(`⚡ Load Balancing: ${chalk.green('Active')}`));
        console.log(chalk.green('='.repeat(50)));
    });
};

// Error handling
process.on('uncaughtException', (err) => {
    console.log(chalk.red.bold('Uncaught Exception:'));
    console.log(chalk.red(err.stack));
});

// Start the server
initializeServer().catch(err => {
    console.error(chalk.red('Failed to initialize server:'), err);
    process.exit(1);
});