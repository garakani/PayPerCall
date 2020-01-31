/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#include "req.h"

bool_t
xdr_str_t (XDR *xdrs, str_t *objp)
{
	register int32_t *buf;

	 if (!xdr_string (xdrs, objp, 512))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_t_string (XDR *xdrs, t_string *objp)
{
	register int32_t *buf;

	 if (!xdr_str_t (xdrs, &objp->data))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_t_pair (XDR *xdrs, t_pair *objp)
{
	register int32_t *buf;

	 if (!xdr_str_t (xdrs, &objp->authorization))
		 return FALSE;
	 if (!xdr_str_t (xdrs, &objp->data))
		 return FALSE;
	return TRUE;
}
