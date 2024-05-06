export function generateMeta(
  total: number,
  take: number,
  page: number,
  url: string,
) {
  return {
    current: {
      take,
      page,
      url: `${ url }?take=${ take }&page=${ page }`,
    },
    next:
      Math.ceil(total / take) > page
        ? {
          take,
          page: page + 1,
          url: `${ url }?take=${ take }&page=${ page + 1 }`,
        }
        : null,
    back:
      page > 1
        ? {
          take,
          page: page - 1,
          url: `${ url }?take=${ take }&page=${ page - 1 }`,
        }
        : null,
    total,
  };
}
