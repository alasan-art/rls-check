export function machineAuthError(req: Request, envName: string, header: string) {
  const expected = Deno.env.get(envName);
  if (!expected || req.headers.get(header) !== expected) return new Response('unauthorized', { status: 401 });
  return null;
}
