/* Header-only gates, before any higher vector call or stock startup. */
static int compatible_exec(const struct Library *library) {
 return library && library->lib_Version==51 && library->lib_NegSize>=169*LIB_VECTSIZE;
}
static int compatible_dos(const struct Library *library) {
 return library && library->lib_Version==50 && library->lib_NegSize>=77*LIB_VECTSIZE;
}
