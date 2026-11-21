//! Overflow-safe 2D geometry and bounded dirty-rectangle damage tracking.

/// A signed 2D point in logical desktop or window-local coordinates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Point {
    pub x: i32,
    pub y: i32,
}

impl Point {
    pub const ZERO: Self = Self { x: 0, y: 0 };

    pub const fn new(x: i32, y: i32) -> Self {
        Self { x, y }
    }
}

/// A non-negative 2D size.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Size {
    pub w: u32,
    pub h: u32,
}

impl Size {
    pub const ZERO: Self = Self { w: 0, h: 0 };

    pub const fn new(w: u32, h: u32) -> Self {
        Self { w, h }
    }
}

/// An axis-aligned integer rectangle `(x, y, w, h)` in logical pixel coordinates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: u32,
    pub h: u32,
}

impl Rect {
    pub const EMPTY: Self = Self { x: 0, y: 0, w: 0, h: 0 };

    pub const fn new(x: i32, y: i32, w: u32, h: u32) -> Self {
        Self { x, y, w, h }
    }

    pub const fn is_empty(self) -> bool {
        self.w == 0 || self.h == 0
    }

    pub fn right(self) -> i64 {
        i64::from(self.x) + i64::from(self.w)
    }

    pub fn bottom(self) -> i64 {
        i64::from(self.y) + i64::from(self.h)
    }

    pub fn area(self) -> u64 {
        u64::from(self.w) * u64::from(self.h)
    }

    pub fn contains_point(self, p: Point) -> bool {
        if self.is_empty() {
            return false;
        }
        let px = i64::from(p.x);
        let py = i64::from(p.y);
        px >= i64::from(self.x) && px < self.right() && py >= i64::from(self.y) && py < self.bottom()
    }

    pub fn intersect(self, other: Self) -> Self {
        if self.is_empty() || other.is_empty() {
            return Self::EMPTY;
        }
        let x0 = i64::from(self.x).max(i64::from(other.x));
        let y0 = i64::from(self.y).max(i64::from(other.y));
        let x1 = self.right().min(other.right());
        let y1 = self.bottom().min(other.bottom());
        if x1 <= x0 || y1 <= y0 {
            return Self::EMPTY;
        }
        let w = (x1 - x0).min(i64::from(u32::MAX)) as u32;
        let h = (y1 - y0).min(i64::from(u32::MAX)) as u32;
        Self { x: x0.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32, y: y0.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32, w, h }
    }

    pub fn union(self, other: Self) -> Self {
        if self.is_empty() {
            return other;
        }
        if other.is_empty() {
            return self;
        }
        let x0 = i64::from(self.x).min(i64::from(other.x));
        let y0 = i64::from(self.y).min(i64::from(other.y));
        let x1 = self.right().max(other.right());
        let y1 = self.bottom().max(other.bottom());
        let w = (x1 - x0).clamp(0, i64::from(u32::MAX)) as u32;
        let h = (y1 - y0).clamp(0, i64::from(u32::MAX)) as u32;
        Self { x: x0.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32, y: y0.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32, w, h }
    }

    pub fn overlaps_or_touches(self, other: Self) -> bool {
        if self.is_empty() || other.is_empty() {
            return false;
        }
        i64::from(self.x) <= other.right()
            && self.right() >= i64::from(other.x)
            && i64::from(self.y) <= other.bottom()
            && self.bottom() >= i64::from(other.y)
    }

    pub fn translate(self, dx: i32, dy: i32) -> Self {
        Self { x: self.x.saturating_add(dx), y: self.y.saturating_add(dy), w: self.w, h: self.h }
    }

    pub fn inset(self, pad: u32) -> Self {
        let twice = pad.saturating_mul(2);
        if self.w <= twice || self.h <= twice {
            return Self::EMPTY;
        }
        Self {
            x: self.x.saturating_add(pad as i32),
            y: self.y.saturating_add(pad as i32),
            w: self.w - twice,
            h: self.h - twice,
        }
    }
}

/// Maximum discrete dirty rectangles kept before coalescing to a bounding box.
pub const MAX_DAMAGE_RECTS: usize = 16;

/// Bounded dirty-rectangle accumulator for damage-tracked compositing.
///
/// Guarantees O(1) memory, zero heap allocation, and automatic merging of overlapping or
/// adjacent rectangles so idle/small updates flush minimal pixels to the display backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DamageSet {
    rects: [Rect; MAX_DAMAGE_RECTS],
    len: usize,
}

impl Default for DamageSet {
    fn default() -> Self {
        Self::new()
    }
}

impl DamageSet {
    pub const fn new() -> Self {
        Self { rects: [Rect::EMPTY; MAX_DAMAGE_RECTS], len: 0 }
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub fn as_slice(&self) -> &[Rect] {
        &self.rects[..self.len]
    }

    pub fn clear(&mut self) {
        self.len = 0;
    }

    /// Add a dirty rectangle, clipping to `bounds` if supplied, and coalescing overlaps.
    pub fn add(&mut self, rect: Rect) {
        if rect.is_empty() {
            return;
        }
        // First check if already covered or mergeable with an existing rect without inflating area wildly.
        let mut r = rect;
        let mut i = 0;
        while i < self.len {
            let cur = self.rects[i];
            if cur.intersect(r) == r {
                // Already fully contained.
                return;
            }
            if r.intersect(cur) == cur {
                // New rect fully contains existing rect: remove existing and keep scanning.
                self.len -= 1;
                self.rects[i] = self.rects[self.len];
                continue;
            }
            if cur.overlaps_or_touches(r) {
                let u = cur.union(r);
                // Merge when union area is close to the sum (avoid exploding into giant dirty rect
                // for two tiny diagonal touches unless they significantly overlap).
                if u.area() <= cur.area().saturating_add(r.area()).saturating_add(4096) {
                    self.len -= 1;
                    self.rects[i] = self.rects[self.len];
                    r = u;
                    // Restart scan with expanded rect.
                    i = 0;
                    continue;
                }
            }
            i += 1;
        }

        if self.len < MAX_DAMAGE_RECTS {
            self.rects[self.len] = r;
            self.len += 1;
        } else {
            // Overflow: coalesce everything into one bounding rectangle.
            let mut bb = r;
            for &existing in self.rects.iter().take(self.len) {
                bb = bb.union(existing);
            }
            self.rects[0] = bb;
            self.len = 1;
        }
    }

    pub fn add_clipped(&mut self, rect: Rect, clip: Rect) {
        let c = rect.intersect(clip);
        if !c.is_empty() {
            self.add(c);
        }
    }

    pub fn bounds(&self) -> Rect {
        let mut bb = Rect::EMPTY;
        for &r in self.rects.iter().take(self.len) {
            bb = bb.union(r);
        }
        bb
    }

    /// Return a new `DamageSet` clipped and translated into `output_bounds`-local coordinates.
    pub fn for_output(&self, output_bounds: Rect) -> Self {
        let mut out = Self::new();
        for &r in self.as_slice() {
            let c = r.intersect(output_bounds);
            if !c.is_empty() {
                out.add(c.translate(-output_bounds.x, -output_bounds.y));
            }
        }
        out
    }
}
