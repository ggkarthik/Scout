import { describe, expect, it } from 'vitest';
import { resolveApiBase } from './base';

describe('resolveApiBase', () => {
  it('defaults to the same-origin api path when no env override is present', () => {
    expect(resolveApiBase('')).toBe('/api');
    expect(resolveApiBase(undefined)).toBe('/api');
  });

  it('preserves an explicit env override and trims trailing slashes', () => {
    expect(resolveApiBase('http://localhost:8080/api/')).toBe('http://localhost:8080/api');
    expect(resolveApiBase('https://api.example.com/base///')).toBe('https://api.example.com/base');
  });
});
