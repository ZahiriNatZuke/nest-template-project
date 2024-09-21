export interface GenerateMetadataParams {
	total: number;
	take: number;
	page: number;
	url: string;
}

export interface Metadata {
	current: {
		take: number;
		page: number;
		url: string;
	};
	next: {
		take: number;
		page: number;
		url: string;
	} | null;
	back: {
		take: number;
		page: number;
		url: string;
	} | null;
	total: number;
}

export const generateMetadata = ({
	total,
	take,
	page,
	url,
}: GenerateMetadataParams): Metadata => {
	return {
		current: {
			take,
			page,
			url: `${url}?take=${take}&page=${page}`,
		},
		next:
			Math.ceil(total / take) > page
				? {
						take,
						page: page + 1,
						url: `${url}?take=${take}&page=${page + 1}`,
					}
				: null,
		back:
			page > 1
				? {
						take,
						page: page - 1,
						url: `${url}?take=${take}&page=${page - 1}`,
					}
				: null,
		total,
	};
};
