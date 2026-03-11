import { useId } from 'react';
import { motion } from 'motion/react';
import { cn } from '../../lib/utils';

interface DotDistortionShaderProps {
  className?: string;
  dotOpacity?: number;
  displacementScale?: number;
}

function DotDistortionShader({
  className,
  dotOpacity = 0.34,
  displacementScale = 18,
}: DotDistortionShaderProps) {
  const id = useId().replace(/:/g, '_');
  const noiseId = `noise_${id}`;
  const filterId = `distort_${id}`;
  const patternId = `dots_${id}`;

  return (
    <div className={cn('dot-distortion-shader', className)} aria-hidden="true">
      <svg className="dot-distortion-svg" viewBox="0 0 100 100" preserveAspectRatio="none">
        <defs>
          <filter id={filterId} x="-20%" y="-20%" width="140%" height="140%">
            <feTurbulence
              id={noiseId}
              type="fractalNoise"
              baseFrequency="0.012 0.02"
              numOctaves={2}
              seed={7}
              result="noise"
            >
              <animate
                attributeName="baseFrequency"
                dur="9s"
                values="0.012 0.020;0.018 0.010;0.010 0.016;0.012 0.020"
                repeatCount="indefinite"
              />
            </feTurbulence>
            <feDisplacementMap in="SourceGraphic" in2="noise" scale={displacementScale} xChannelSelector="R" yChannelSelector="G" />
          </filter>

          <pattern id={patternId} width="8" height="8" patternUnits="userSpaceOnUse">
            <circle cx="1.6" cy="1.6" r="1.15" fill="currentColor" />
          </pattern>
        </defs>

        <motion.rect
          x="0"
          y="0"
          width="100"
          height="100"
          fill={`url(#${patternId})`}
          filter={`url(#${filterId})`}
          initial={{ opacity: dotOpacity - 0.08 }}
          animate={{ opacity: [dotOpacity - 0.08, dotOpacity + 0.08, dotOpacity - 0.08] }}
          transition={{ duration: 6, repeat: Infinity, ease: 'easeInOut' }}
        />
      </svg>
    </div>
  );
}

export default DotDistortionShader;
