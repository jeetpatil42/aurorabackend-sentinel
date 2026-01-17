/**
 * AI Explanation Engine - Hybrid Style
 * Generates short bullets + final summary line
 */
import { RiskSnapshot } from './engine';
export interface ExplanationInputs {
    snapshot: RiskSnapshot;
    audioInputs?: {
        rms: number;
        pitchVariance: number;
        spikeCount: number;
    };
    motionInputs?: {
        accelerationMagnitude: number;
        jitter: number;
    };
    location?: {
        lat?: number;
        lng?: number;
        zoneName?: string;
        isNormalZone?: boolean;
        normal_zone?: boolean;
    };
    time?: Date;
}
/**
 * Generate explanation bullets + summary
 */
export declare function generateExplanation(inputs: ExplanationInputs): string[];
//# sourceMappingURL=explain.d.ts.map