COMPILE_DEPS = CORE_DEPS + JACKSON + CLI + [
	"@jackson_core_asl//jar",
    "@jackson_mapper_asl//jar",
    "//protocols/pof/pofio:onos-protocols-pof-pofio",
	'//protocols/pof/api:onos-protocols-pof-api',
	'//apps/seanet/api:onos-apps-seanet-api',
]

osgi_jar (
    deps = COMPILE_DEPS,
    import_packages = '*,org.onosproject.cli.net',
)

BUNDLES = [
    '//apps/seanet/api:onos-apps-seanet-api',
	'//apps/seanet/seanrs:onos-apps-seanet-seanrs',
]

onos_app (
    title = 'SEANET Name Resolution Service App',
    category = 'Traffic Steering',
    url = 'http://onosproject.org',
    description = 'SEANET Name Resolution Service App.',
    included_bundles = BUNDLES,
)
