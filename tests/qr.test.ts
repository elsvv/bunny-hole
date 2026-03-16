// tests/qr.test.ts
import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { _buildMatrix } from '../src/qr.ts';

describe('QR code generator', () => {
  it('produces correct dimensions for version 1 (short text)', () => {
    const grid = _buildMatrix('HELLO');
    // Version 1: 21x21
    assert.equal(grid.length, 21);
    assert.equal(grid[0].length, 21);
  });

  it('produces correct dimensions for version 2 (18+ chars)', () => {
    const grid = _buildMatrix('Hello, World! 12345');
    // Version 2: 25x25
    assert.equal(grid.length, 25);
    assert.equal(grid[0].length, 25);
  });

  it('scales up versions for longer text', () => {
    // ~100 chars should require version 5+ (capacity: v4=78, v5=106)
    const text = 'https://example.com/' + 'x'.repeat(80);
    const grid = _buildMatrix(text);
    // Version 5: 37x37
    assert.equal(grid.length, 37);
    assert.equal(grid[0].length, 37);
  });

  it('handles a realistic key-share URL (~150 chars)', () => {
    // Simulate a mode 0x03 URL
    const text = 'https://bunny-hole.example/#' + 'A'.repeat(120);
    const grid = _buildMatrix(text);
    // 148 chars => version 6 (cap 134 is too small) => version 7 (cap 154)
    // Version 7: 17 + 7*4 = 45x45
    assert.equal(grid.length, 45);
    assert.equal(grid[0].length, 45);
  });

  it('throws for text exceeding version 10 capacity', () => {
    const text = 'x'.repeat(272);
    assert.throws(() => _buildMatrix(text), /too long/);
  });

  it('has finder patterns in correct corners', () => {
    const grid = _buildMatrix('TEST');
    const n = grid.length; // 21 for version 1

    // Top-left finder: (0,0)-(6,6) border should be dark
    for (let i = 0; i < 7; i++) {
      assert.equal(grid[0][i], 1, `top-left finder top border [0][${i}]`);
      assert.equal(grid[6][i], 1, `top-left finder bottom border [6][${i}]`);
      assert.equal(grid[i][0], 1, `top-left finder left border [${i}][0]`);
      assert.equal(grid[i][6], 1, `top-left finder right border [${i}][6]`);
    }

    // Top-right finder: (0, n-7)-(6, n-1)
    for (let i = 0; i < 7; i++) {
      assert.equal(grid[0][n - 7 + i], 1, `top-right finder top border`);
      assert.equal(grid[6][n - 7 + i], 1, `top-right finder bottom border`);
    }

    // Bottom-left finder: (n-7, 0)-(n-1, 6)
    for (let i = 0; i < 7; i++) {
      assert.equal(grid[n - 7][i], 1, `bottom-left finder top border`);
      assert.equal(grid[n - 1][i], 1, `bottom-left finder bottom border`);
    }
  });

  it('produces only 0s and 1s in the grid', () => {
    const grid = _buildMatrix('https://example.com/test');
    for (let r = 0; r < grid.length; r++) {
      for (let c = 0; c < grid[r].length; c++) {
        assert.ok(grid[r][c] === 0 || grid[r][c] === 1, `grid[${r}][${c}] = ${grid[r][c]}`);
      }
    }
  });

  it('different inputs produce different grids', () => {
    const g1 = _buildMatrix('AAA');
    const g2 = _buildMatrix('BBB');
    // Both version 1 (21x21), but should have different data modules
    let differ = false;
    for (let r = 0; r < g1.length && !differ; r++) {
      for (let c = 0; c < g1[r].length && !differ; c++) {
        if (g1[r][c] !== g2[r][c]) differ = true;
      }
    }
    assert.ok(differ, 'Different inputs should produce different QR codes');
  });
});
