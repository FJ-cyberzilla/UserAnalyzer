#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <algorithm>
#include <curl/curl.h>
#include <thread>
#include <chrono>
#include <regex>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <future>
#include <atomic>
#include <mutex>
#include <random>
#include <ctime>
#include <json/json.h>  // For JSON parsing (install libjsoncpp-dev)

// Enhanced structures for better data organization
struct PlatformResult {
    std::string name;
    std::string url;
    bool exists;
    int httpCode;
    double responseTime;
    std::string errorMsg;
    std::string profileData;
    std::map<std::string, std::string> metadata;
};

struct SecurityAnalysis {
    int riskScore;
    std::vector<std::string> vulnerabilities;
    std::vector<std::string> recommendations;
    std::map<std::string, int> exposureMetrics;
};

struct NLPInsights {
    std::vector<std::string> detectedTopics;
    std::map<std::string, float> sentimentScores;
    std::vector<std::string> personalityTraits;
    std::map<std::string, int> contentCategories;
};

class AdvancedFootprintAnalyzer {
private:
    std::string email;
    std::string username;
    std::vector<PlatformResult> results;
    SecurityAnalysis security;
    NLPInsights nlpData;
    std::atomic<int> completedChecks{0};
    std::mutex resultsMutex;
    std::vector<std::string> userAgents;
    std::random_device rd;
    std::mt19937 gen;

    // Enhanced callback with response time tracking
    struct CallbackData {
        std::string* response;
        std::chrono::steady_clock::time_point startTime;
        double* responseTime;
    };

    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userData) {
        CallbackData* data = static_cast<CallbackData*>(userData);
        size_t totalSize = size * nmemb;
        data->response->append((char*)contents, totalSize);
        return totalSize;
    }

    // Initialize user agents for rotation
    void initializeUserAgents() {
        userAgents = {
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0"
        };
    }

    std::string getRandomUserAgent() {
        std::uniform_int_distribution<> dis(0, userAgents.size() - 1);
        return userAgents[dis(gen)];
    }

    // Enhanced URL checking with comprehensive error handling
    PlatformResult checkUrlAdvanced(const std::string& name, const std::string& url,
                                  const std::string& negativePattern) {
        PlatformResult result;
        result.name = name;
        result.url = url;
        result.exists = false;
        result.httpCode = 0;
        result.responseTime = 0.0;

        CURL* curl = curl_easy_init();
        if (!curl) {
            result.errorMsg = "Failed to initialize CURL";
            return result;
        }

        std::string response;
        CallbackData callbackData;
        callbackData.response = &response;
        callbackData.responseTime = &result.responseTime;
        callbackData.startTime = std::chrono::steady_clock::now();

        try {
            // Enhanced CURL options
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &callbackData);
            curl_easy_setopt(curl, CURLOPT_USERAGENT, getRandomUserAgent().c_str());
            curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
            curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
            curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
            curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "gzip, deflate");

            // Headers to appear more legitimate
            struct curl_slist* headers = nullptr;
            headers = curl_slist_append(headers, "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
            headers = curl_slist_append(headers, "Accept-Language: en-US,en;q=0.5");
            headers = curl_slist_append(headers, "Accept-Encoding: gzip, deflate");
            headers = curl_slist_append(headers, "Connection: keep-alive");
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

            auto startTime = std::chrono::steady_clock::now();
            CURLcode res = curl_easy_perform(curl);
            auto endTime = std::chrono::steady_clock::now();

            result.responseTime = std::chrono::duration<double, std::milli>(endTime - startTime).count();

            long httpCode = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
            result.httpCode = static_cast<int>(httpCode);

            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);

            if (res != CURLE_OK) {
                result.errorMsg = "CURL Error: " + std::string(curl_easy_strerror(res));
                return result;
            }

            // Advanced response analysis
            if (httpCode == 200) {
                // Check for negative patterns (indicating profile doesn't exist)
                bool hasNegativePattern = response.find(negativePattern) != std::string::npos;

                // Additional checks for common "not found" indicators
                std::vector<std::string> notFoundIndicators = {
                    "user not found", "profile not found", "page not found",
                    "doesn't exist", "not available", "suspended", "deactivated"
                };

                bool hasNotFoundIndicator = std::any_of(notFoundIndicators.begin(), notFoundIndicators.end(),
                    [&response](const std::string& indicator) {
                        std::string lowerResponse = response;
                        std::transform(lowerResponse.begin(), lowerResponse.end(), lowerResponse.begin(), ::tolower);
                        return lowerResponse.find(indicator) != std::string::npos;
                    });

                result.exists = !hasNegativePattern && !hasNotFoundIndicator;
                result.profileData = response.substr(0, std::min(response.length(), size_t(2000))); // Store excerpt

                // Extract metadata
                extractMetadata(response, result.metadata);
            } else if (httpCode == 404) {
                result.exists = false;
                result.errorMsg = "Profile not found (404)";
            } else if (httpCode == 403) {
                result.exists = false;
                result.errorMsg = "Access forbidden (403)";
            } else if (httpCode >= 500) {
                result.errorMsg = "Server error (" + std::to_string(httpCode) + ")";
            } else {
                result.errorMsg = "Unexpected HTTP code: " + std::to_string(httpCode);
            }

        } catch (const std::exception& e) {
            result.errorMsg = "Exception: " + std::string(e.what());
            curl_easy_cleanup(curl);
        }

        return result;
    }

    // Extract metadata from HTML content
    void extractMetadata(const std::string& html, std::map<std::string, std::string>& metadata) {
        // Extract title
        std::regex titleRegex("<title[^>]*>([^<]+)</title>", std::regex_constants::icase);
        std::smatch match;
        if (std::regex_search(html, match, titleRegex)) {
            metadata["title"] = match[1].str();
        }

        // Extract meta description
        std::regex descRegex("<meta\\s+name=[\"']description[\"']\\s+content=[\"']([^\"']+)[\"']", std::regex_constants::icase);
        if (std::regex_search(html, match, descRegex)) {
            metadata["description"] = match[1].str();
        }

        // Extract Open Graph data
        std::regex ogRegex("<meta\\s+property=[\"']og:([^\"']+)[\"']\\s+content=[\"']([^\"']+)[\"']", std::regex_constants::icase);
        auto begin = std::sregex_iterator(html.begin(), html.end(), ogRegex);
        auto end = std::sregex_iterator();
        for (std::sregex_iterator i = begin; i != end; ++i) {
            std::smatch match = *i;
            metadata["og:" + match[1].str()] = match[2].str();
        }
    }

    // Enhanced email validation with comprehensive checks
    bool validateEmailAdvanced(const std::string& email) const {
        // RFC 5322 compliant regex (simplified)
        std::regex emailRegex(
            R"(^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$)"
        );

        if (!std::regex_match(email, emailRegex)) {
            return false;
        }

        // Additional checks
        if (email.length() > 254) return false; // RFC limit
        if (email.find("..") != std::string::npos) return false; // No consecutive dots
        if (email.front() == '.' || email.back() == '.') return false; // No leading/trailing dots

        size_t atPos = email.find('@');
        if (atPos == std::string::npos) return false;

        std::string localPart = email.substr(0, atPos);
        std::string domainPart = email.substr(atPos + 1);

        if (localPart.length() > 64) return false; // RFC limit for local part
        if (domainPart.length() > 253) return false; // RFC limit for domain part

        return true;
    }

    // NLP Analysis of profile content
    void performNLPAnalysis() {
        // Initialize empty maps that will be populated with analysis results
        std::map<std::string, int> topicFrequency;        // Will store topic -> frequency count
        std::map<std::string, float> platformSentiments; // Will store platform -> sentiment score

        // Process each platform result
        for (const auto& result : results) {
            if (result.exists && !result.profileData.empty()) {
                analyzeContent(result.profileData, result.name, topicFrequency, platformSentiments);
            }
        }

        // Convert topic frequency map to vector of relevant topics
        nlpData.detectedTopics.clear(); // Start with empty vector
        for (const auto& topic : topicFrequency) {
            if (topic.second > 2) { // Threshold for relevance
                nlpData.detectedTopics.push_back(topic.first);
            }
        }

        nlpData.sentimentScores = platformSentiments;
        generatePersonalityInsights();
    }

    void analyzeContent(const std::string& content, const std::string& platform,
                       std::map<std::string, int>& topicFreq,
                       std::map<std::string, float>& sentiments) {

        // Simple keyword-based topic detection
        std::vector<std::pair<std::string, std::vector<std::string>>> topics = {
            {"Technology", {"code", "programming", "software", "tech", "developer", "engineer"}},
            {"Photography", {"photo", "camera", "lens", "shot", "picture", "image"}},
            {"Music", {"music", "song", "album", "band", "artist", "sound"}},
            {"Sports", {"game", "team", "player", "sport", "match", "tournament"}},
            {"Travel", {"travel", "trip", "vacation", "journey", "explore", "visit"}},
            {"Food", {"food", "recipe", "cook", "restaurant", "meal", "cuisine"}},
            {"Art", {"art", "design", "creative", "paint", "draw", "artwork"}},
            {"Business", {"business", "entrepreneur", "startup", "company", "work"}}
        };

        std::string lowerContent = content;
        std::transform(lowerContent.begin(), lowerContent.end(), lowerContent.begin(), ::tolower);

        for (const auto& topic : topics) {
            int count = 0;
            for (const auto& keyword : topic.second) {
                size_t pos = 0;
                while ((pos = lowerContent.find(keyword, pos)) != std::string::npos) {
                    count++;
                    pos += keyword.length();
                }
            }
            if (count > 0) {
                topicFreq[topic.first] += count;
            }
        }

        // Simple sentiment analysis
        std::vector<std::string> positiveWords = {"great", "awesome", "love", "amazing", "excellent", "good"};
        std::vector<std::string> negativeWords = {"bad", "terrible", "hate", "awful", "horrible", "worst"};

        int positiveCount = 0, negativeCount = 0;
        for (const auto& word : positiveWords) {
            size_t pos = 0;
            while ((pos = lowerContent.find(word, pos)) != std::string::npos) {
                positiveCount++;
                pos += word.length();
            }
        }
        for (const auto& word : negativeWords) {
            size_t pos = 0;
            while ((pos = lowerContent.find(word, pos)) != std::string::npos) {
                negativeCount++;
                pos += word.length();
            }
        }

        float sentiment = 0.0f;
        if (positiveCount + negativeCount > 0) {
            sentiment = (float)(positiveCount - negativeCount) / (positiveCount + negativeCount);
        }
        sentiments[platform] = sentiment;
    }

    void generatePersonalityInsights() {
        // Simple personality trait inference based on platform presence and content
        std::map<std::string, int> traitScores;

        for (const auto& result : results) {
            if (result.exists) {
                if (result.name == "GitHub") {
                    traitScores["Technical"] += 3;
                    traitScores["Analytical"] += 2;
                } else if (result.name == "Instagram") {
                    traitScores["Creative"] += 2;
                    traitScores["Social"] += 2;
                } else if (result.name == "LinkedIn") {
                    traitScores["Professional"] += 3;
                    traitScores["Ambitious"] += 2;
                } else if (result.name == "Twitter") {
                    traitScores["Communicative"] += 2;
                    traitScores["Opinionated"] += 1;
                }
            }
        }

        for (const auto& trait : traitScores) {
            if (trait.second >= 2) {
                nlpData.personalityTraits.push_back(trait.first);
            }
        }
    }

    // Security risk analysis
    void performSecurityAnalysis() {
        // Reset security analysis data
        security.riskScore = 0;
        security.vulnerabilities.clear();          // Empty the vulnerabilities vector
        security.recommendations.clear();          // Empty the recommendations vector
        security.exposureMetrics.clear();          // Empty the exposure metrics map

        int exposedPlatforms = 0;
        int professionalPlatforms = 0;
        int socialPlatforms = 0;

        for (const auto& result : results) {
            if (result.exists) {
                exposedPlatforms++;
                security.exposureMetrics[result.name] = 1;

                if (result.name == "LinkedIn" || result.name == "GitHub") {
                    professionalPlatforms++;
                } else if (result.name == "Instagram" || result.name == "Twitter" || result.name == "Facebook") {
                    socialPlatforms++;
                }

                // Check for potential security issues in metadata
                for (const auto& meta : result.metadata) {
                    if (meta.first.find("email") != std::string::npos ||
                        meta.first.find("phone") != std::string::npos) {
                        security.vulnerabilities.push_back("Potential PII exposure on " + result.name);
                        security.riskScore += 10;
                    }
                }
            }
        }

        // Calculate risk score based on exposure
        security.riskScore += exposedPlatforms * 5;
        if (exposedPlatforms > 7) {
            security.riskScore += 15;
            security.vulnerabilities.push_back("High digital footprint - many platforms exposed");
        }

        if (socialPlatforms > 3) {
            security.riskScore += 10;
            security.vulnerabilities.push_back("Multiple social media accounts increase attack surface");
        }

        // Generate recommendations
        if (exposedPlatforms > 5) {
            security.recommendations.push_back("Consider auditing and reducing your digital footprint");
        }
        if (security.riskScore > 30) {
            security.recommendations.push_back("Enable two-factor authentication on all accounts");
            security.recommendations.push_back("Review privacy settings on all platforms");
        }

        security.recommendations.push_back("Regularly monitor your digital presence");
        security.recommendations.push_back("Use unique, strong passwords for each platform");
    }

    // Save detailed report
    void saveDetailedReport() const {
        std::ofstream reportFile("digital_footprint_report.json");
        if (!reportFile.is_open()) {
            std::cerr << "Warning: Could not save detailed report to file" << std::endl;
            return;
        }

        // Create JSON report
        Json::Value report;
        report["email"] = email;
        report["username"] = username;
        report["timestamp"] = std::time(nullptr);

        Json::Value platforms(Json::arrayValue);
        for (const auto& result : results) {
            Json::Value platform;
            platform["name"] = result.name;
            platform["url"] = result.url;
            platform["exists"] = result.exists;
            platform["httpCode"] = result.httpCode;
            platform["responseTime"] = result.responseTime;
            platform["errorMsg"] = result.errorMsg;

            Json::Value metadata;
            for (const auto& meta : result.metadata) {
                metadata[meta.first] = meta.second;
            }
            platform["metadata"] = metadata;
            platforms.append(platform);
        }
        report["platforms"] = platforms;

        // Security analysis
        Json::Value securityJson;
        securityJson["riskScore"] = security.riskScore;
        Json::Value vulns(Json::arrayValue);
        for (const auto& vuln : security.vulnerabilities) {
            vulns.append(vuln);
        }
        securityJson["vulnerabilities"] = vulns;
        report["security"] = securityJson;

        // NLP insights
        Json::Value nlpJson;
        Json::Value topics(Json::arrayValue);
        for (const auto& topic : nlpData.detectedTopics) {
            topics.append(topic);
        }
        nlpJson["topics"] = topics;
        report["nlp"] = nlpJson;

        reportFile << report;
        reportFile.close();

        std::cout << "🫆 Detailed report saved to: digital_footprint_report.json" << std::endl;
    }

public:
    AdvancedDigitalFootprintAnalyzer(const std::string& email)
        : email(email), gen(rd()) {
        if (!validateEmailAdvanced(email)) {
            throw std::invalid_argument("Invalid email format");
        }

        size_t atPos = email.find('@');
        username = (atPos != std::string::npos) ? email.substr(0, atPos) : email;
        initializeUserAgents();
    }

    void performComprehensiveAnalysis() {
        std::cout << "\n🚀 Advanced Digital Footprint Analyzer 🚀" << std::endl;
        std::cout << "===========================================" << std::endl;
        std::cout << "📨 Email: " << email << std::endl;
        std::cout << "👤 Username: " << username << std::endl;
        std::time_t currentTime = std::time(nullptr);
        std::cout << "🕐 Analysis started at: " << std::ctime(&currentTime);
        std::cout << std::endl;

        // Enhanced platform list with more comprehensive coverage
        std::vector<std::tuple<std::string, std::string, std::string>> platforms = {
            // Social Media
            {"Instagram", "https://www.instagram.com/" + username, "The link you followed may be broken"},
            {"Twitter", "https://twitter.com/" + username, "page doesn't exist"},
            {"Facebook", "https://www.facebook.com/" + username, "content isn't available"},
            {"LinkedIn", "https://www.linkedin.com/in/" + username, "page not found"},
            {"TikTok", "https://www.tiktok.com/@" + username, "Couldn't find this account"},
            {"Snapchat", "https://www.snapchat.com/add/" + username, "Page not found"},

            // Professional/Tech
            {"GitHub", "https://github.com/" + username, "404 \"This is not the web page"},
            {"Stack Overflow", "https://stackoverflow.com/users/" + username, "page not found"},
            {"Behance", "https://www.behance.net/" + username, "404"},
            {"Dribbble", "https://dribbble.com/" + username, "404"},

            // Media/Content
            {"YouTube", "https://www.youtube.com/@" + username, "This channel does not exist"},
            {"Twitch", "https://www.twitch.tv/" + username, "page not found"},
            {"SoundCloud", "https://soundcloud.com/" + username, "404"},
            {"Spotify", "https://open.spotify.com/user/" + username, "Page not found"},
            {"Medium", "https://medium.com/@" + username, "404"},

            // Other
            {"Reddit", "https://www.reddit.com/user/" + username, "page not found"},
            {"Pinterest", "https://www.pinterest.com/" + username, "Page not found"},
            {"Flickr", "https://www.flickr.com/people/" + username, "Not Found"},
            {"Vimeo", "https://vimeo.com/" + username, "404 Not Found"},
            {"Discord", "https://discord.com/users/" + username, "404"}
        };

        std::cout << "🔎, Scanning " << platforms.size() << " platforms..." << std::endl;
        std::cout << std::string(60, '=') << std::endl;

        // Progress indicator
        std::cout << std::left << std::setw(18) << "PLATFORM"
                  << std::setw(12) << "STATUS"
                  << std::setw(15) << "RESPONSE TIME"
                  << "DETAILS" << std::endl;
        std::cout << std::string(60, '-') << std::endl;

        // Use thread pool for concurrent checking
        std::vector<std::future<PlatformResult>> futures;
        const int maxConcurrency = 5; // Limit to avoid being rate-limited
        int currentBatch = 0;

        for (size_t i = 0; i < platforms.size(); i += maxConcurrency) {
            // Process batch
            futures.clear();
            size_t batchEnd = std::min(i + maxConcurrency, platforms.size());

            for (size_t j = i; j < batchEnd; ++j) {
                const auto& platform = platforms[j];
                futures.push_back(std::async(std::launch::async, [this, platform]() {
                    return checkUrlAdvanced(std::get<0>(platform), std::get<1>(platform), std::get<2>(platform));
                }));
            }

            // Collect results from batch
            for (auto& future : futures) {
                PlatformResult result = future.get();

                {
                    std::lock_guard<std::mutex> lock(resultsMutex);
                    results.push_back(result);
                }

                // Display result
                std::cout << std::left << std::setw(18) << result.name;
                if (result.exists) {
                    std::cout << std::setw(12) << "✅ FOUND";
                } else {
                    std::cout << std::setw(12) << "⛔ Not found";
                }

                std::cout << std::setw(15) << (std::to_string(static_cast<int>(result.responseTime)) + "ms");

                if (!result.errorMsg.empty()) {
                    std::cout << "(" << result.errorMsg << ")";
                } else if (result.exists) {
                    std::cout << result.url;
                }
                std::cout << std::endl;

                completedChecks++;
            }

            // Small delay between batches to be respectful
            if (i + maxConcurrency < platforms.size()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(2000));
            }
        }

        std::cout << std::string(60, '=') << std::endl;

        // Perform advanced analysis
        std::cout << "\n👽 Performing AI Analysis..." << std::endl;
        performNLPAnalysis();
        performSecurityAnalysis();

        displayAdvancedResults();
        saveDetailedReport();
    }

private:
    void displayAdvancedResults() {
        int foundProfiles = std::count_if(results.begin(), results.end(),
                                        [](const PlatformResult& r) { return r.exists; });

        std::cout << "\n📊 ANALYSIS RESULTS" << std::endl;
        std::cout << "===================" << std::endl;
        std::cout << "🎯 Profiles Found: " << foundProfiles << "/" << results.size() << std::endl;

        // Calculate average response time
        double avgResponseTime = 0.0;
        int validResponses = 0;
        for (const auto& result : results) {
            if (result.responseTime > 0) {
                avgResponseTime += result.responseTime;
                validResponses++;
            }
        }
        if (validResponses > 0) {
            avgResponseTime /= validResponses;
            std::cout << "⚡ Avg Response Time: " << std::fixed << std::setprecision(1)
                      << avgResponseTime << "ms" << std::endl;
        }

        // Security Analysis
        std::cout << "\n🛡️  SECURITY ANALYSIS" << std::endl;
        std::cout << "Risk Score: " << security.riskScore << "/100 ";
        if (security.riskScore < 20) {
            std::cout << "(🟢 Low Risk)" << std::endl;
        } else if (security.riskScore < 50) {
            std::cout << "(🟡 Medium Risk)" << std::endl;
        } else {
            std::cout << "(🔴 High Risk)" << std::endl;
        }

        if (!security.vulnerabilities.empty()) {
            std::cout << "⚠️  Vulnerabilities:" << std::endl;
            for (const auto& vuln : security.vulnerabilities) {
                std::cout << "   • " << vuln << std::endl;
            }
        }

        if (!security.recommendations.empty()) {
            std::cout << "💡 Recommendations:" << std::endl;
            for (const auto& rec : security.recommendations) {
                std::cout << "   • " << rec << std::endl;
            }
        }

        // NLP Insights
        if (!nlpData.detectedTopics.empty() || !nlpData.personalityTraits.empty()) {
            std::cout << "\n🤖 AI INSIGHTS" << std::endl;

            if (!nlpData.detectedTopics.empty()) {
                std::cout << "🏷️  Detected Topics: ";
                for (size_t i = 0; i < nlpData.detectedTopics.size(); ++i) {
                    std::cout << nlpData.detectedTopics[i];
                    if (i < nlpData.detectedTopics.size() - 1) std::cout << ", ";
                }
                std::cout << std::endl;
            }

            if (!nlpData.personalityTraits.empty()) {
                std::cout << "👤 Personality Traits: ";
                for (size_t i = 0; i < nlpData.personalityTraits.size(); ++i) {
                    std::cout << nlpData.personalityTraits[i];
                    if (i < nlpData.personalityTraits.size() - 1) std::cout << ", ";
                }
                std::cout << std::endl;
            }

            if (!nlpData.sentimentScores.empty()) {
                std::cout << "😊 Sentiment Analysis:" << std::endl;
                for (const auto& sentiment : nlpData.sentimentScores) {
                    std::cout << "   " << sentiment.first << ": ";
                    if (sentiment.second > 0.1) {
                        std::cout << "Positive (" << std::fixed << std::setprecision(2)
                                  << sentiment.second << ")" << std::endl;
                    } else if (sentiment.second < -0.1) {
                        std::cout << "Negative (" << std::fixed << std::setprecision(2)
                                  << sentiment.second << ")" << std::endl;
                    } else {
                        std::cout << "Neutral (" << std::fixed << std::setprecision(2)
                                  << sentiment.second << ")" << std::endl;
                    }
                }
            }
        }

        // Platform-specific insights
        std::cout << "\n🌐 PLATFORM INSIGHTS" << std::endl;

        // Initialize empty categories that will be populated below
        std::map<std::string, std::vector<std::string>> categoryGroups = {
            {"Professional", std::vector<std::string>()},      // Will contain LinkedIn, Behance, etc.
            {"Social Media", std::vector<std::string>()},      // Will contain Instagram, Twitter, etc.
            {"Content Creation", std::vector<std::string>()},  // Will contain YouTube, Medium, etc.
            {"Development", std::vector<std::string>()}        // Will contain GitHub, Stack Overflow, etc.
        };

        for (const auto& result : results) {
            if (result.exists) {
                if (result.name == "LinkedIn" || result.name == "Behance" || result.name == "Stack Overflow") {
                    categoryGroups["Professional"].push_back(result.name);
                } else if (result.name == "Instagram" || result.name == "Twitter" || result.name == "Facebook" || result.name == "TikTok") {
                    categoryGroups["Social Media"].push_back(result.name);
                } else if (result.name == "YouTube" || result.name == "Twitch" || result.name == "SoundCloud" || result.name == "Medium") {
                    categoryGroups["Content Creation"].push_back(result.name);
                } else if (result.name == "GitHub" || result.name == "Stack Overflow") {
                    categoryGroups["Development"].push_back(result.name);
                }
            }
        }

        for (const auto& category : categoryGroups) {
            if (!category.second.empty()) {
                std::cout << "   " << category.first << ": ";
                for (size_t i = 0; i < category.second.size(); ++i) {
                    std::cout << category.second[i];
                    if (i < category.second.size() - 1) std::cout << ", ";
                }
                std::cout << std::endl;
            }
        }

        std::cout << "\n🔗 FOUND PROFILES:" << std::endl;
        for (const auto& result : results) {
            if (result.exists) {
                std::cout << "   • " << result.name << ": " << result.url;
                if (!result.metadata.empty() && result.metadata.find("title") != result.metadata.end()) {
                    std::cout << " (\"" << result.metadata.at("title") << "\")";
                }
                std::cout << std::endl;
            }
        }
    }
};

// Enhanced error handling wrapper
class AnalyzerManager {
private:
    std::unique_ptr<AdvancedDigitalFootprintAnalyzer> analyzer;

public:
    bool initializeAnalyzer(const std::string& email) {
        try {
            analyzer = std::make_unique<AdvancedDigitalFootprintAnalyzer>(email);
            return true;
        } catch (const std::invalid_argument& e) {
            std::cerr << "❌ Email Validation Error: " << e.what() << std::endl;
            return false;
        } catch (const std::exception& e) {
            std::cerr << "❌ Initialization Error: " << e.what() << std::endl;
            return false;
        }
    }

    void runAnalysis() {
        if (!analyzer) {
            std::cerr << "❌ Analyzer not initialized" << std::endl;
            return;
        }

        try {
            analyzer->performComprehensiveAnalysis();
        } catch (const std::exception& e) {
            std::cerr << "❌ Analysis Error: " << e.what() << std::endl;
            std::cout << "\n🔧 Attempting recovery..." << std::endl;
            // Could implement recovery logic here
        }
    }
};

// Enhanced input validation and user interface
class UserInterface {
public:
    static std::string getEmailInput() {
        std::string email;

        std::cout << "🔍 Advanced Digital Footprint Analyzer" << std::endl;
        std::cout << "===============================================" << std::endl;
        std::cout << "🌟 AI-Powered Privacy & Security Analysis 🌟\n" << std::endl;

        std::cout << "Features included:" << std::endl;
        std::cout << "  ✓ 20+ Platform Coverage" << std::endl;
        std::cout << "  ✓ Security Risk Analysis" << std::endl;
        std::cout << "  ✓ AI Content Analysis" << std::endl;
        std::cout << "  ✓ NLP Sentiment Detection" << std::endl;
        std::cout << "  ✓ Personality Insights" << std::endl;
        std::cout << "  ✓ Detailed JSON Report" << std::endl;
        std::cout << "  ✓ Privacy Recommendations\n" << std::endl;

        while (true) {
            std::cout << "Enter your email address: ";
            std::getline(std::cin, email);

            // Trim whitespace
            email.erase(0, email.find_first_not_of(" \t\n\r\f\v"));
            email.erase(email.find_last_not_of(" \t\n\r\f\v") + 1);

            if (email.empty()) {
                std::cout << "❌ Email cannot be empty. Please try again.\n" << std::endl;
                continue;
            }

            if (email == "quit" || email == "exit") {
                std::cout << "Powered by F.J™ - Cyberzilla®" << std::endl;
                exit(0);
            }

            // Basic format check
            if (email.find('@') == std::string::npos || email.find('.') == std::string::npos) {
                std::cout << "❌ Please enter a valid email address format.\n" << std::endl;
                continue;
            }

            break;
        }

        return email;
    }

    static bool confirmAnalysis(const std::string& email) {
        std::cout << "\n⚠️  PRIVACY NOTICE" << std::endl;
        std::cout << "This tool will:" << std::endl;
        std::cout << "  • Search for public profiles associated with: " << email << std::endl;
        std::cout << "  • Analyze publicly available content" << std::endl;
        std::cout << "  • Generate security and privacy recommendations" << std::endl;
        std::cout << "  • Save results to a local JSON file" << std::endl;
        std::cout << "\nNo personal data is transmitted to external servers." << std::endl;

        std::string response;
        std::cout << "\nProceed with analysis? (y/N): ";
        std::getline(std::cin, response);

        return (response == "y" || response == "Y" || response == "yes" || response == "YES");
    }
};

int main() {
    // Initialize curl globally
    curl_global_init(CURL_GLOBAL_DEFAULT);

    try {
        UserInterface ui;
        std::string email = ui.getEmailInput();

        if (!ui.confirmAnalysis(email)) {
            std::cout << "Analysis cancelled by user." << std::endl;
            curl_global_cleanup();
            return 0;
        }

        AnalyzerManager manager;
        if (!manager.initializeAnalyzer(email)) {
            curl_global_cleanup();
            return 1;
        }

        auto startTime = std::chrono::steady_clock::now();
        manager.runAnalysis();
        auto endTime = std::chrono::steady_clock::now();

        auto duration = std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime);

        std::cout << "\n⚡ Analysis Complete!" << std::endl;
        std::cout << "⏱️  Total time: " << duration.count() << " seconds" << std::endl;
        std::cout << "\n💡 Tips for better privacy:" << std::endl;
        std::cout << "   • Regularly audit your digital presence" << std::endl;
        std::cout << "   • Use privacy-focused search engines" << std::endl;
        std::cout << "   • Enable two-factor authentication everywhere" << std::endl;
        std::cout << "   • Review and update privacy settings regularly" << std::endl;
        std::cout << "   • Consider using different usernames for different purposes" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "❌ Fatal Error: " << e.what() << std::endl;
        curl_global_cleanup();
        return 1;
    }

    curl_global_cleanup();
    return 0;
