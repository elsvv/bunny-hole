// tests/contacts.test.ts
import { describe, it, beforeEach } from 'node:test';
import { strict as assert } from 'node:assert';

// Mock localStorage for Node.js
const store: Record<string, string> = {};
(globalThis as any).localStorage = {
  getItem: (k: string) => store[k] ?? null,
  setItem: (k: string, v: string) => { store[k] = v; },
  removeItem: (k: string) => { delete store[k]; },
};

import { getContacts, addContact, removeContact } from '../src/contacts.ts';
import type { Contact } from '../src/contacts.ts';

describe('contacts', () => {
  beforeEach(() => {
    delete store['bh_contacts'];
  });

  it('returns empty array when no contacts', () => {
    assert.deepStrictEqual(getContacts(), []);
  });

  it('adds a contact', () => {
    addContact('Alice', 'abc123pubkey');
    const contacts = getContacts();
    assert.equal(contacts.length, 1);
    assert.equal(contacts[0].label, 'Alice');
    assert.equal(contacts[0].pubkey, 'abc123pubkey');
    assert.ok(contacts[0].added_at);
  });

  it('adds multiple contacts', () => {
    addContact('Alice', 'key1');
    addContact('Bob', 'key2');
    assert.equal(getContacts().length, 2);
  });

  it('removes a contact by pubkey', () => {
    addContact('Alice', 'key1');
    addContact('Bob', 'key2');
    removeContact('key1');
    const contacts = getContacts();
    assert.equal(contacts.length, 1);
    assert.equal(contacts[0].label, 'Bob');
  });

  it('rejects duplicate pubkey', () => {
    addContact('Alice', 'key1');
    assert.throws(() => addContact('Bob', 'key1'), /already exists/);
  });
});
