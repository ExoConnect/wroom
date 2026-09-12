// Join tokens grant room membership and identity; they are minted out of band
// and are opaque to the client (decision 16 — auth behind an interface).
//
// For M0 there is no auth provider and rooms are ephemeral shareable links, so
// we mint an unsigned "dev token" client-side that carries the room id and the
// display name. The exact wire format is a placeholder until wroomd's token
// verification lands — this function is the single point to change.
export function mintDevToken(room: string, displayName: string): string {
  // Dev format: plaintext "room:displayName" — matches wroomd's
  // DevTokenVerifier. Only the first ':' separates; names may contain more.
  return `${room}:${displayName}`
}
