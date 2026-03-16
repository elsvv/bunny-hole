// src/contacts.ts

const STORAGE_KEY = 'bh_contacts';

export interface Contact {
  label: string;
  pubkey: string;
  added_at: string; // ISO date
}

export function getContacts(): Contact[] {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) return [];
  return JSON.parse(raw);
}

function saveContacts(contacts: Contact[]): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(contacts));
}

export function addContact(label: string, pubkey: string): void {
  const contacts = getContacts();
  if (contacts.some(c => c.pubkey === pubkey)) {
    throw new Error('Contact with this public key already exists');
  }
  contacts.push({ label, pubkey, added_at: new Date().toISOString() });
  saveContacts(contacts);
}

export function renameContact(pubkey: string, newLabel: string): void {
  const contacts = getContacts();
  const contact = contacts.find(c => c.pubkey === pubkey);
  if (contact) {
    contact.label = newLabel;
    saveContacts(contacts);
  }
}

export function removeContact(pubkey: string): void {
  const contacts = getContacts().filter(c => c.pubkey !== pubkey);
  saveContacts(contacts);
}
