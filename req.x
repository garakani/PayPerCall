typedef string str_t<4096>;

struct t_string {
	str_t data;
};

struct t_pair {
	str_t authorization;
	str_t data;
};

program REQ_PROG{
	version REQ_VERS{
                t_string req_receipt(t_string)=1;
		t_string req(t_pair)=2;
	}=1;
}=0x23451111;
