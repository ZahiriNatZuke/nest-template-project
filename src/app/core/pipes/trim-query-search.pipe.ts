import { Injectable, PipeTransform } from '@nestjs/common';

@Injectable()
export class TrimQuerySearchPipe implements PipeTransform {
	transform(value: string | undefined) {
		if (typeof value === 'undefined') return '';
		return value.trim().toLowerCase();
	}
}
