try:
    from ninja.throttling import AnonRateThrottle, AuthRateThrottle
    print("ninja.throttling imports OK")
except Exception as e:
    print("Error:", e)

try:
    from ninja_extra import throttle
    print("ninja_extra.throttle imports OK")
except Exception as e:
    print("Error:", e)
