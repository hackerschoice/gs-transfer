

void DP_init(char *filename, FILE *out);
void DP_update(off_t total, off_t cur_pos, int force_update);
void DP_finish(void);
void DP_test(void);