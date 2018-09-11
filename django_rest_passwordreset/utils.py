
def get_client_masked_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if not x_forwarded_for:
        ip = request.META.get('REMOTE_ADDR')

    elif ',' in x_forwarded_for:
        # See https://github.com/Miserlou/Zappa/issues/772:
        ip = x_forwarded_for.split(',')[-2]

    else:
        ip = x_forwarded_for

    # Mask ip according https://support.google.com/analytics/answer/2763052?hl=en
    ip = ip.strip()
    ip = '.'.join(ip.split('.')[:-1]) + '.0'
    return ip
