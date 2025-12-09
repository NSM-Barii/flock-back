// FlockBack - Cyberpunk Hacker Background Effects
// Matrix rain + Cyber grid + Particles

class HackerBackground {
    constructor() {
        this.canvases = {};
        this.contexts = {};
        this.init();
    }

    init() {
        // Create canvas layers
        this.createCanvas('matrix', 1);
        this.createCanvas('grid', 2);
        this.createCanvas('particles', 3);

        // Start animations
        this.initMatrixRain();
        this.initCyberGrid();
        this.initParticles();

        // Handle window resize
        window.addEventListener('resize', () => this.handleResize());
    }

    createCanvas(id, zIndex) {
        const canvas = document.createElement('canvas');
        canvas.id = `bg-${id}`;
        canvas.className = 'bg-canvas';
        canvas.style.zIndex = zIndex;
        document.body.insertBefore(canvas, document.body.firstChild);

        this.canvases[id] = canvas;
        this.contexts[id] = canvas.getContext('2d');

        this.resizeCanvas(id);
    }

    resizeCanvas(id) {
        const canvas = this.canvases[id];
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    }

    handleResize() {
        Object.keys(this.canvases).forEach(id => this.resizeCanvas(id));
        this.matrixColumns = Math.floor(window.innerWidth / 20);
        this.matrixDrops = new Array(this.matrixColumns).fill(1);
    }

    // ==================== MATRIX RAIN ====================
    initMatrixRain() {
        const canvas = this.canvases.matrix;
        const ctx = this.contexts.matrix;

        this.matrixChars = '01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン';
        this.matrixColumns = Math.floor(canvas.width / 20);
        this.matrixDrops = new Array(this.matrixColumns).fill(1);

        this.animateMatrix();
    }

    animateMatrix() {
        const canvas = this.canvases.matrix;
        const ctx = this.contexts.matrix;

        // Fade effect
        ctx.fillStyle = 'rgba(10, 14, 39, 0.05)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);

        // Draw characters
        ctx.font = '15px monospace';

        for (let i = 0; i < this.matrixDrops.length; i++) {
            const char = this.matrixChars[Math.floor(Math.random() * this.matrixChars.length)];
            const x = i * 20;
            const y = this.matrixDrops[i] * 20;

            // Color gradient (blue to cyan)
            const opacity = Math.random() * 0.5 + 0.3;
            ctx.fillStyle = `rgba(95, 159, 255, ${opacity})`;

            ctx.fillText(char, x, y);

            // Reset drop randomly
            if (y > canvas.height && Math.random() > 0.975) {
                this.matrixDrops[i] = 0;
            }

            this.matrixDrops[i]++;
        }

        requestAnimationFrame(() => this.animateMatrix());
    }

    // ==================== CYBER GRID ====================
    initCyberGrid() {
        this.gridOffset = 0;
        this.animateGrid();
    }

    animateGrid() {
        const canvas = this.canvases.grid;
        const ctx = this.contexts.grid;

        ctx.clearRect(0, 0, canvas.width, canvas.height);

        const gridSize = 50;
        const vanishingY = canvas.height * 0.4;
        const perspective = 0.6;

        ctx.strokeStyle = 'rgba(95, 159, 255, 0.1)';
        ctx.lineWidth = 1;

        // Horizontal lines (with perspective)
        for (let i = 0; i < 20; i++) {
            const y = vanishingY + (i * gridSize) + (this.gridOffset % gridSize);
            const scale = 1 - (i / 20) * perspective;

            ctx.beginPath();
            const startX = canvas.width / 2 - (canvas.width / 2) * scale;
            const endX = canvas.width / 2 + (canvas.width / 2) * scale;

            ctx.moveTo(startX, y);
            ctx.lineTo(endX, y);
            ctx.stroke();
        }

        // Vertical lines (converging to center)
        const numVerticals = 20;
        for (let i = 0; i < numVerticals; i++) {
            ctx.beginPath();
            const startX = (canvas.width / numVerticals) * i;
            const endX = canvas.width / 2;

            ctx.moveTo(startX, vanishingY);
            ctx.lineTo(endX, canvas.height);
            ctx.stroke();
        }

        this.gridOffset += 0.5;

        requestAnimationFrame(() => this.animateGrid());
    }

    // ==================== PARTICLES ====================
    initParticles() {
        this.particles = [];

        // Create particles
        for (let i = 0; i < 50; i++) {
            this.particles.push({
                x: Math.random() * window.innerWidth,
                y: Math.random() * window.innerHeight,
                size: Math.random() * 2 + 1,
                speedX: (Math.random() - 0.5) * 0.5,
                speedY: (Math.random() - 0.5) * 0.5,
                opacity: Math.random() * 0.5 + 0.3,
                color: this.getRandomColor()
            });
        }

        this.animateParticles();
    }

    getRandomColor() {
        const colors = [
            'rgba(95, 159, 255,',   // Blue
            'rgba(168, 85, 247,',   // Purple
            'rgba(255, 71, 87,',    // Red
            'rgba(16, 185, 129,'    // Green
        ];
        return colors[Math.floor(Math.random() * colors.length)];
    }

    animateParticles() {
        const canvas = this.canvases.particles;
        const ctx = this.contexts.particles;

        ctx.clearRect(0, 0, canvas.width, canvas.height);

        this.particles.forEach((p, index) => {
            // Update position
            p.x += p.speedX;
            p.y += p.speedY;

            // Wrap around screen
            if (p.x < 0) p.x = canvas.width;
            if (p.x > canvas.width) p.x = 0;
            if (p.y < 0) p.y = canvas.height;
            if (p.y > canvas.height) p.y = 0;

            // Draw particle with glow
            ctx.fillStyle = `${p.color} ${p.opacity})`;
            ctx.shadowBlur = 10;
            ctx.shadowColor = `${p.color} 1)`;

            ctx.beginPath();
            ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
            ctx.fill();

            ctx.shadowBlur = 0;

            // Draw connections to nearby particles
            this.particles.slice(index + 1).forEach(p2 => {
                const dx = p.x - p2.x;
                const dy = p.y - p2.y;
                const distance = Math.sqrt(dx * dx + dy * dy);

                if (distance < 150) {
                    ctx.strokeStyle = `${p.color} ${0.2 * (1 - distance / 150)})`;
                    ctx.lineWidth = 0.5;
                    ctx.beginPath();
                    ctx.moveTo(p.x, p.y);
                    ctx.lineTo(p2.x, p2.y);
                    ctx.stroke();
                }
            });
        });

        requestAnimationFrame(() => this.animateParticles());
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    new HackerBackground();
});
