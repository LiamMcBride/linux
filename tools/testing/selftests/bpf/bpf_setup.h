struct bpf_link_and_obj {
    struct bpf_link* link;
    struct bpf_object* obj;
}

void bpf_cleanup_program(struct bpf_link_and_obj bpf_lao);

struct bpf_link_and_obj bpf_program_load_and_attach(char* obj_file, char* prog_name);