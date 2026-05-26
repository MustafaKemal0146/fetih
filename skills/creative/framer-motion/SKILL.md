---
name: framer-motion
description: "Framer Motion React animation library skill — declarative animations, gestures, layout transitions, scroll-triggered animations, variants, AnimatePresence, and performance optimization."
tags: [react, animation, framer-motion, frontend, motion, gestures, layout, scroll, drag, typescript]
triggers:
  - "framer motion"
  - "react animasyon"
  - "declarative animation"
  - "layout animation"
  - "AnimatePresence"
  - "motion.div"
  - "spring animation"
  - "scroll animation"
  - "drag and drop"
  - "gesture"
  - "page transition"
  - "whileHover"
  - "useAnimation"
  - "useMotionValue"
category: creative
adapted_for: fetih
source: framer/motion (npm: framer-motion)
---

# Framer Motion — Declarative React Animation

Framer Motion is a production-ready animation library for React. Simple declarative API, powerful layout animations, gestures, and server-side rendering support.

**Version:** 12.40.0  
**Package:** `framer-motion`  
**License:** MIT

## Installation

```bash
npm install framer-motion
# or
yarn add framer-motion
# or
pnpm add framer-motion
```

## Core Concepts

### 1. The `motion` Component

Every HTML/SVG element becomes animatable by prefixing with `motion.`:

```tsx
import { motion } from "framer-motion"

<motion.div
  animate={{ x: 100, opacity: 1 }}
  initial={{ x: 0, opacity: 0 }}
  transition={{ duration: 0.5 }}
/>
```

### 2. AnimatePresence (Exit Animations)

Wrap components that conditionally render to animate their removal:

```tsx
import { AnimatePresence, motion } from "framer-motion"

<AnimatePresence>
  {isVisible && (
    <motion.div
      initial={{ opacity: 0, scale: 0.8 }}
      animate={{ opacity: 1, scale: 1 }}
      exit={{ opacity: 0, scale: 0.8 }}
      transition={{ duration: 0.3 }}
    >
      Content
    </motion.div>
  )}
</AnimatePresence>
```

### 3. Variants (Reusable Animation States)

Define named animation states for cleaner code:

```tsx
const variants = {
  hidden: { opacity: 0, y: 20 },
  visible: { opacity: 1, y: 0 },
  exit: { opacity: 0, y: -20 }
}

<motion.div
  variants={variants}
  initial="hidden"
  animate="visible"
  exit="exit"
/>
```

### 4. Gestures (Hover, Tap, Drag)

```tsx
<motion.button
  whileHover={{ scale: 1.05 }}
  whileTap={{ scale: 0.95 }}
  transition={{ type: "spring", stiffness: 400, damping: 17 }}
>
  Click Me
</motion.button>

<motion.div
  drag
  dragConstraints={{ left: 0, right: 300, top: 0, bottom: 300 }}
  whileDrag={{ scale: 1.1, boxShadow: "0 10px 30px rgba(0,0,0,0.2)" }}
/>
```

### 5. Layout Animations

Automatically animate layout changes:

```tsx
<motion.div layout>
  {/* Content that changes size/position */}
</motion.div>

// Shared layout animation (morphing between elements)
<motion.div layoutId="shared-element">
  {selected ? <ExpandedView /> : <CompactView />}
</motion.div>
```

### 6. Scroll-Triggered Animations

```tsx
import { useScroll, useTransform, motion } from "framer-motion"

function ParallaxSection() {
  const { scrollYProgress } = useScroll()
  const scale = useTransform(scrollYProgress, [0, 1], [0.8, 1])
  const opacity = useTransform(scrollYProgress, [0, 0.5, 1], [0, 1, 1])

  return <motion.div style={{ scale, opacity }}>Content</motion.div>
}

// Scroll-linked progress bar
function ProgressBar() {
  const { scrollYProgress } = useScroll()
  return <motion.div style={{ scaleX: scrollYProgress, transformOrigin: "left" }} />
}
```

### 7. `whileInView` (Intersection Observer)

Animate elements when they enter the viewport:

```tsx
<motion.div
  initial={{ opacity: 0, y: 40 }}
  whileInView={{ opacity: 1, y: 0 }}
  viewport={{ once: true, margin: "-50px" }}
  transition={{ duration: 0.6 }}
>
  Appears on scroll
</motion.div>
```

## Common Patterns

### Staggered Children

```tsx
const container = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: { staggerChildren: 0.1, delayChildren: 0.2 }
  }
}

const item = {
  hidden: { opacity: 0, y: 20 },
  visible: { opacity: 1, y: 0 }
}

<motion.ul variants={container} initial="hidden" animate="visible">
  {items.map(item => (
    <motion.li key={item.id} variants={item}>{item.text}</motion.li>
  ))}
</motion.ul>
```

### Page Transitions (Next.js / React Router)

```tsx
// With Next.js App Router (template.tsx)
import { motion } from "framer-motion"

export default function Template({ children }: { children: React.ReactNode }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -20 }}
      transition={{ duration: 0.3 }}
    >
      {children}
    </motion.div>
  )
}
```

### Spring Physics

Spring animations feel more natural than duration-based:

```tsx
<motion.div
  animate={{ x: 100 }}
  transition={{
    type: "spring",
    stiffness: 100,   // Spring strength (default: 100)
    damping: 10,      // Resistance (default: 10)
    mass: 1,          // Object weight (default: 1)
    bounce: 0.25      // Bounciness (0-1)
  }}
/>

// Preset springs
transition={{ type: "spring", stiffness: 300, damping: 30 }} // Snappy
transition={{ type: "spring", stiffness: 50, damping: 20 }}  // Bouncy
```

### Keyframes

```tsx
<motion.div
  animate={{
    x: [0, 100, 50, 100, 0],
    scale: [1, 1.2, 0.9, 1.1, 1],
    rotate: [0, 0, 270, 270, 0]
  }}
  transition={{ duration: 2, repeat: Infinity }}
/>
```

## Performance Optimization

### 1. Use `layout="position"` Instead of `layout`

When only position changes (not size):

```tsx
<motion.div layout="position" />
```

### 2. `useReducedMotion`

Respect accessibility preferences:

```tsx
import { useReducedMotion } from "framer-motion"

const shouldReduceMotion = useReducedMotion()

<motion.div
  animate={shouldReduceMotion ? {} : { x: 100 }}
  transition={{ duration: 0.5 }}
/>
```

### 3. Hardware-Accelerated Properties Only

Animate only `transform` and `opacity` for 60fps:
- ✅ `x`, `y`, `scale`, `rotate`, `opacity`
- ❌ `width`, `height`, `top`, `left`, `backgroundColor`

### 4. Lazy Motion (Tree Shaking)

```tsx
import { m } from "framer-motion"  // Smaller bundle

// Use m.div instead of motion.div
<m.div animate={{ opacity: 1 }} />
```

### 5. `will-change` Hint

```tsx
<motion.div style={{ willChange: "transform" }} />
```

## Best Practices

1. **Wrap all animations in `<AnimatePresence>`** for proper exit animations
2. **Use variants** for reusable animation states across components
3. **Prefer spring** over duration-based transitions for natural feel
4. **Set `viewport={{ once: true }}`** on scroll animations to avoid re-triggering
5. **Always provide `exit` prop** when using conditional rendering
6. **Test with `prefers-reduced-motion`** for accessibility
7. **Use `layoutId`** for shared element transitions between pages
8. **Keep animations between 150-400ms** for UI feedback

## Debugging

```tsx
// Visualize layout animations
<motion.div layout layoutRoot />

// Log animation lifecycle
<motion.div
  onAnimationStart={() => console.log("started")}
  onAnimationComplete={() => console.log("completed")}
/>
```

## Common Gotchas

| Issue | Fix |
|-------|-----|
| Layout animation jitter | Add `layoutId` to animating elements |
| Exit animation not playing | Wrap with `<AnimatePresence>` |
| Children not staggering | Put `staggerChildren` on container's `transition` |
| Transform origin off | Set `style={{ originX: 0.5, originY: 0.5 }}` |
| Hover state flickering | Use `whileHover` not CSS `:hover` |

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: ee743008151ab4a2
-->
