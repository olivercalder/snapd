if [[ "$SPREAD_STORE_USER" =~ .*stg-dummydev.* ]] ; then
    # staging fully expired macaroon for dummydev
    SPREAD_STORE_EXPIRED_MACAROON="MDAzMWxvY2F0aW9uIG15YXBwcy5kZXZlbG9wZXIuc3RhZ2luZy51YnVudHUuY29tCjAwMTZpZGVudGlmaWVyIE15QXBwcwowMDUzY2lkIG15YXBwcy5kZXZlbG9wZXIuc3RhZ2luZy51YnVudHUuY29tfHZhbGlkX3NpbmNlfDIwMTctMTItMDhUMTQ6MTM6MTIuMTIyMTY5CjAyZDFjaWQgeyJzZWNyZXQiOiAiZ1pmMlJqRldZZ1lPaC9EQ1Z5S2F6a2xGdnowanpSSlFqVVdMeVQrTjVXQVE5UWtqMnZJNUFIK01uckJsY082MVlVZmlYY2lwWGFqTmFhVmdyTkxOdFJUOVpocXFwZHNlL0puMk93RUxITmdBMXVBSHBiZ3grREY0WDdmOXBPbTkyNjFXWUFwVFFYd2M2MnBNazM0MjJVOTJNaUFmbmJ5bWl4cFJWQ2pYRklOeEZrWkdtY2dKY2l1QWFCckhYQnErT0dvZWRHMWlhWCt1REdMbExFZ1Z3ZWhhd2V3Q3VrcVB2TjVJMUk1R2EvTzAyQnNvWU5NYmk4YmYzaUx0SDVaNE5GNEhzV1EyMUl6alZUZDBkTEh0WW9YV0tJakNsbnJTLy84RThoZ2F5SmtaNEpwNERpRDlET2NjaGpJQktJdVlucWdoSDZ1aU9Zd2ErakIzMVlwaStscnNSQXVMM0tTSENIZUlHaUliSUFaWjUrWXhKeGozWW00NlN0SlN4OFpnOTVzbmc2c3ErQU9HMVo4R2dqOHhVZy9pMHkxWk50RUFHSkhaTWV6NTFhdUlUZ3BrdlRXOWdoaWVVR0ozUVgzWnVhSFlhWEcvamFSVTl3Nit3SWxLM0ZTRWdRRmIyaHBqczRwV0pjdThaWVUvdjJwd2drZXlDWmlpa3Fyc0gwcXZwbVhHWTJVc3hleE1iMERUOVgwKzdNaVBhS2E3RGQ4MjhJTHdKb3oxeitRSTFvOGZDVVR0L09QbGgvUjZOTG5RV2ROWFVhdkpFYUFIR2pSYkF6TFZTWmxRTFZPTGtDVnFJMUNYOGdBdU9YblE3YXhQeEp0NHRJcThVYU1vU3AzWE1KbVBsWkFiTkZJWExPUlJxTHp6SEErdlM2Q2lLZ3JtY1JlYzBmVHhJK1U9IiwgInZlcnNpb24iOiAxfQowMDUxdmlkIPgmrpio2QwhVRlhlXhJA_MgWTSoT6c2kWWUU-3wiIVBn-P27TUhRKWZY-4P3ZUzElJ1mhDfba9UKi-SuHRu2s3OWBQ-WHSGUwowMDIwY2wgbG9naW4uc3RhZ2luZy51YnVudHUuY29tCjAwNGZjaWQgbXlhcHBzLmRldmVsb3Blci5zdGFnaW5nLnVidW50dS5jb218ZXhwaXJlc3wyMDE3LTEyLTA4VDE0OjEzOjExLjY2MDg0MAowMDQzY2lkIG15YXBwcy5kZXZlbG9wZXIuc3RhZ2luZy51YnVudHUuY29tfGFjbHxbInBhY2thZ2VfYWNjZXNzIl0KMDAyZnNpZ25hdHVyZSCnOjXc6nQKlsIKsVRsYe6p0NE_83ReApoTluTcp_RuMQo"

    SPREAD_STORE_EXPIRED_DISCHARGE="MDAyNmxvY2F0aW9uIGxvZ2luLnN0YWdpbmcudWJ1bnR1LmNvbQowMmQ4aWRlbnRpZmllciB7InNlY3JldCI6ICJnWmYyUmpGV1lnWU9oL0RDVnlLYXprbEZ2ejBqelJKUWpVV0x5VCtONVdBUTlRa2oydkk1QUgrTW5yQmxjTzYxWVVmaVhjaXBYYWpOYWFWZ3JOTE50UlQ5WmhxcXBkc2UvSm4yT3dFTEhOZ0ExdUFIcGJneCtERjRYN2Y5cE9tOTI2MVdZQXBUUVh3YzYycE1rMzQyMlU5Mk1pQWZuYnltaXhwUlZDalhGSU54RmtaR21jZ0pjaXVBYUJySFhCcStPR29lZEcxaWFYK3VER0xsTEVnVndlaGF3ZXdDdWtxUHZONUkxSTVHYS9PMDJCc29ZTk1iaThiZjNpTHRINVo0TkY0SHNXUTIxSXpqVlRkMGRMSHRZb1hXS0lqQ2xuclMvLzhFOGhnYXlKa1o0SnA0RGlEOURPY2NoaklCS0l1WW5xZ2hINnVpT1l3YStqQjMxWXBpK2xyc1JBdUwzS1NIQ0hlSUdpSWJJQVpaNStZeEp4ajNZbTQ2U3RKU3g4Wmc5NXNuZzZzcStBT0cxWjhHZ2o4eFVnL2kweTFaTnRFQUdKSFpNZXo1MWF1SVRncGt2VFc5Z2hpZVVHSjNRWDNadWFIWWFYRy9qYVJVOXc2K3dJbEszRlNFZ1FGYjJocGpzNHBXSmN1OFpZVS92MnB3Z2tleUNaaWlrcXJzSDBxdnBtWEdZMlVzeGV4TWIwRFQ5WDArN01pUGFLYTdEZDgyOElMd0pvejF6K1FJMW84ZkNVVHQvT1BsaC9SNk5MblFXZE5YVWF2SkVhQUhHalJiQXpMVlNabFFMVk9Ma0NWcUkxQ1g4Z0F1T1huUTdheFB4SnQ0dElxOFVhTW9TcDNYTUptUGxaQWJORklYTE9SUnFMenpIQSt2UzZDaUtncm1jUmVjMGZUeEkrVT0iLCAidmVyc2lvbiI6IDF9CjAxMzZjaWQgbG9naW4uc3RhZ2luZy51YnVudHUuY29tfGFjY291bnR8ZXlKMWMyVnlibUZ0WlNJNklDSjBaWE4wTFhOdVlYQmtMWE4wWnkxa2RXMXRlV1JsZGlJc0lDSnZjR1Z1YVdRaU9pQWlSRUpNY25wQ2N5SXNJQ0prYVhOd2JHRjVibUZ0WlNJNklDSjBaWE4wSUhOdVlYQmtJSE4wWVdkcGJtY2daSFZ0YlhrZ1pHVjJaV3h2Y0dWeUlpd2dJbVZ0WVdsc0lqb2dJbk5oYlhWbGJHVXVjR1ZrY205dWFTdDBaWE4wTFhOdVlYQmtMWE4wWnkxa2RXMXRlV1JsZGtCallXNXZibWxqWVd3dVkyOXRJaXdnSW1selgzWmxjbWxtYVdWa0lqb2dkSEoxWlgwPQowMDQ4Y2lkIGxvZ2luLnN0YWdpbmcudWJ1bnR1LmNvbXx2YWxpZF9zaW5jZXwyMDE3LTEyLTA4VDE0OjEzOjE4LjIxMzgwNAowMDQ2Y2lkIGxvZ2luLnN0YWdpbmcudWJ1bnR1LmNvbXxsYXN0X2F1dGh8MjAxNy0xMi0wOFQxNDoxMzoxOC4yMTM4MDQKMDA0NGNpZCBsb2dpbi5zdGFnaW5nLnVidW50dS5jb218ZXhwaXJlc3wyMDE4LTEyLTA4VDE0OjEzOjE4LjIxMzgzMAowMDJmc2lnbmF0dXJlIHWyFzBRHHqsJQf8yzE3TQBLdvkK6t3677OXkPPno_IbCg"

else
    # production fully expired macaroon for dummydev
    SPREAD_STORE_EXPIRED_MACAROON="MDAyOWxvY2F0aW9uIG15YXBwcy5kZXZlbG9wZXIudWJ1bnR1LmNvbQowMDE2aWRlbnRpZmllciBNeUFwcHMKMDA0YmNpZCBteWFwcHMuZGV2ZWxvcGVyLnVidW50dS5jb218dmFsaWRfc2luY2V8MjAxNy0xMi0xMVQxNjo1NToyMi43NjAzNDEKMDE3ZGNpZCB7InNlY3JldCI6ICJPSFV3R1M5WERVdy9tWWxVWnpsUTA3T3NyYW5Nb0RkcWFsT2cxZmMxNWh2Y0JuWTAyOGovcFJBb0RjMFlVRVMvMkFGNDF1Q2EvME9xM0hTaVZvZENkMTh1TmNqcXp6SFlSMjJRbzg1Y1lEaVN5OGR4UXB2RG9oZzVXdjlBUnFZdENuYlJWMkdHb0RQMmxhUXhaL1dSZ3hKYnJZUElkSjdqOUYwU0MxbFd6bkc0VWVwVGVjRzRVak1aV3pycHhtTDd2OXhrelVvcmZGM3hZakZZejJvYTRsYVNJZWJYOUk4L0ZmNDRkZUt2dkZCWDhZSUJkenNBYkQxWEZkQlZjUW92TW02WUozWHNQZHl4REFURmVGcmxKRjdLZHVGdjBURVEyT2htVlN0ODlMY010aU9XZjFnYjEzcFNKaDh2SUU0YzhjalhOVEM5bVZlckRJZFo2YTRvY2c9PSIsICJ2ZXJzaW9uIjogMX0KMDA1MXZpZCDhEaH_dhs2aoldbGCJ3q1ZsWfwWzjKqiIpbuZdxxuOVaFjYG_0M2qXCPiSaPMDiNizkwiMPp6UzERhqh2FH_F0x3cACq5yA1sKMDAxOGNsIGxvZ2luLnVidW50dS5jb20KMDA0N2NpZCBteWFwcHMuZGV2ZWxvcGVyLnVidW50dS5jb218ZXhwaXJlc3wyMDE3LTEyLTExVDE2OjU1OjIyLjM0NDU2OAowMDNiY2lkIG15YXBwcy5kZXZlbG9wZXIudWJ1bnR1LmNvbXxhY2x8WyJwYWNrYWdlX2FjY2VzcyJdCjAwMmZzaWduYXR1cmUgD3hKjPMj-oRn5vSLNo48hIeyBsF7o7S858suOP9tKw0K"

    SPREAD_STORE_EXPIRED_DISCHARGE="MDAxZWxvY2F0aW9uIGxvZ2luLnVidW50dS5jb20KMDE4NGlkZW50aWZpZXIgeyJzZWNyZXQiOiAiT0hVd0dTOVhEVXcvbVlsVVp6bFEwN09zcmFuTW9EZHFhbE9nMWZjMTVodmNCblkwMjhqL3BSQW9EYzBZVUVTLzJBRjQxdUNhLzBPcTNIU2lWb2RDZDE4dU5janF6ekhZUjIyUW84NWNZRGlTeThkeFFwdkRvaGc1V3Y5QVJxWXRDbmJSVjJHR29EUDJsYVF4Wi9XUmd4SmJyWVBJZEo3ajlGMFNDMWxXem5HNFVlcFRlY0c0VWpNWld6cnB4bUw3djl4a3pVb3JmRjN4WWpGWXoyb2E0bGFTSWViWDlJOC9GZjQ0ZGVLdnZGQlg4WUlCZHpzQWJEMVhGZEJWY1Fvdk1tNllKM1hzUGR5eERBVEZlRnJsSkY3S2R1RnYwVEVRMk9obVZTdDg5TGNNdGlPV2YxZ2IxM3BTSmg4dklFNGM4Y2pYTlRDOW1WZXJESWRaNmE0b2NnPT0iLCAidmVyc2lvbiI6IDF9CjAxMTJjaWQgbG9naW4udWJ1bnR1LmNvbXxhY2NvdW50fGV5SjFjMlZ5Ym1GdFpTSTZJQ0owWlhOMExYTnVZWEJrTFdSMWJXMTVaR1YySWl3Z0ltOXdaVzVwWkNJNklDSmpRM0JTU0ZGeUlpd2dJbVJwYzNCc1lYbHVZVzFsSWpvZ0luUmxjM1FnYzI1aGNHUWdaSFZ0YlhrZ1pHVjJJaXdnSW1WdFlXbHNJam9nSW5OaGJYVmxiR1V1Y0dWa2NtOXVhU3QwWlhOMExYTnVZWEJrTFdSMWJXMTVaR1YyUUdOaGJtOXVhV05oYkM1amIyMGlMQ0FpYVhOZmRtVnlhV1pwWldRaU9pQjBjblZsZlE9PQowMDQwY2lkIGxvZ2luLnVidW50dS5jb218dmFsaWRfc2luY2V8MjAxNy0xMi0xMVQxNjo1NToyMy45NTIxOTQKMDAzZWNpZCBsb2dpbi51YnVudHUuY29tfGxhc3RfYXV0aHwyMDE3LTEyLTExVDE2OjU1OjIzLjk1MjE5NAowMDNjY2lkIGxvZ2luLnVidW50dS5jb218ZXhwaXJlc3wyMDE4LTEyLTExVDE2OjU1OjIzLjk1MjIyMAowMDJmc2lnbmF0dXJlIMQb2VBXVx2mewXpATMr5qBzkFoQqE2NCOPfT8p6pic-Cg"

fi
