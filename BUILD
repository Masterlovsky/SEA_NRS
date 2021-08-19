COMPILE_DEPS = CORE_DEPS + JACKSON + [
    "@jackson_core_asl//jar",
     "@jackson_mapper_asl//jar",
    "//protocols/pof/pofio:onos-protocols-pof-pofio",
	'//protocols/pof/api:onos-protocols-pof-api',
]


osgi_jar_with_tests (
    deps = COMPILE_DEPS,
)

BUNDLES = [
	'//apps/seanet/sea_nrs:onos-apps-seanet-sea_nrs',
]

onos_app (
    title = 'SEANET Name Resolution Service App',
    category = 'Test App',
    url = 'http://onosproject.org',
    description = 'SENET Name Resolution Service App.',
    included_bundles = BUNDLES,
)
