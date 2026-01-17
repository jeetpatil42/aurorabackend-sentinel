"use strict";
/**
 * AI Explanation Engine - Hybrid Style
 * Generates short bullets + final summary line
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateExplanation = generateExplanation;
/**
 * Generate explanation bullets + summary
 */
function generateExplanation(inputs) {
    const { snapshot, audioInputs, motionInputs, location, time } = inputs;
    const bullets = [];
    // Audio interpretation
    if (audioInputs) {
        const dbLevel = Math.round(audioInputs.rms * 100); // Convert 0-1 to 0-100 dB approximation
        if (snapshot.audio.score > 20) {
            bullets.push(`Loud audio spike detected (${dbLevel} dB)`);
        }
        else if (snapshot.audio.score > 10) {
            bullets.push(`Moderate audio activity (${dbLevel} dB)`);
        }
        else {
            bullets.push(`Normal audio levels (${dbLevel} dB)`);
        }
    }
    // Motion interpretation
    if (motionInputs) {
        const jerkValue = motionInputs.accelerationMagnitude.toFixed(1);
        if (snapshot.motion.score > 15) {
            bullets.push(`Sudden jerk motion (${jerkValue}g)`);
        }
        else if (snapshot.motion.score > 8) {
            bullets.push(`Moderate motion detected (${jerkValue}g)`);
        }
        else {
            bullets.push(`Normal movement (${jerkValue}g)`);
        }
    }
    // Location: zone name if inside polygon, or normal zone
    if (location?.zoneName) {
        const zoneType = location.zoneName.toLowerCase().includes('high') ? 'high-risk' : 'low-risk';
        bullets.push(`Inside ${zoneType} zone: ${location.zoneName}`);
    }
    else if (location?.isNormalZone || location?.normal_zone) {
        bullets.push('User is outside all predefined risk zones (normal area)');
    }
    else if (location?.lat && location?.lng) {
        bullets.push(`Location: ${location.lat.toFixed(4)}, ${location.lng.toFixed(4)}`);
    }
    // Time-of-day multiplier
    if (time) {
        const hour = time.getHours();
        if (hour >= 0 && hour < 4) {
            bullets.push('Night-time multiplier applied');
        }
        else if (hour >= 20 && hour < 24) {
            bullets.push('Evening-time multiplier applied');
        }
        else if (hour >= 4 && hour < 6) {
            bullets.push('Early morning multiplier applied');
        }
        else {
            bullets.push('Daytime multiplier applied');
        }
    }
    // Final summary line
    const riskLevel = snapshot.level === 'high' ? 'High Risk' :
        snapshot.level === 'medium' ? 'Medium Risk' : 'Low Risk';
    bullets.push(`→ Final Score: ${snapshot.total.toFixed(0)}/100 (${riskLevel})`);
    return bullets;
}
//# sourceMappingURL=explain.js.map